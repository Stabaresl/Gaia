"""
clean_benign.py — Limpieza y validación del CSV benigno generado por cicflowmeter.

Uso:
    python clean_benign.py --input /app/csv_output/combined/ --output benign_clean.csv

Qué hace:
    1. Une todos los CSV de la carpeta combined/
    2. Elimina NaN e infinitos (cicflowmeter los genera en flows incompletos)
    3. Elimina duplicados exactos
    4. Asegura columna Label = BENIGN
    5. Muestra estadísticas del resultado
    6. Guarda CSV listo para merge con dataset de ataques
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd


# ─── Columnas que cicflowmeter Python genera ───────────────────────────────
# Si tu versión genera nombres distintos, ajusta aquí.
EXPECTED_COLS = 84  # CICFlowMeter estándar


def load_csvs(input_path: Path) -> pd.DataFrame:
    """Carga uno o varios CSVs y los une."""
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = sorted(input_path.rglob("*.csv"))
    else:
        print(f"ERROR: {input_path} no existe")
        sys.exit(1)

    if not files:
        print(f"ERROR: No se encontraron CSVs en {input_path}")
        sys.exit(1)

    print(f"Cargando {len(files)} archivo(s)...")
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            if len(df) > 0:
                dfs.append(df)
                print(f"  {f.name}: {len(df):,} filas, {len(df.columns)} columnas")
            else:
                print(f"  {f.name}: VACÍO — omitido")
        except Exception as e:
            print(f"  {f.name}: ERROR ({e}) — omitido")

    if not dfs:
        print("ERROR: Ningún CSV válido encontrado")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal cargado: {len(combined):,} filas, {len(combined.columns)} columnas")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Pipeline de limpieza completo."""
    original_len = len(df)
    print("\n─── Limpieza ───────────────────────────────────────")

    # 1. Normalizar nombres de columnas (strip espacios)
    df.columns = df.columns.str.strip()

    # 2. Asegurar columna Label = BENIGN
    label_col = None
    for candidate in ["Label", "label", "LABEL", "class", "Class"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        print("  Columna Label no encontrada → creando con valor BENIGN")
        df["Label"] = "BENIGN"
    else:
        if label_col != "Label":
            df = df.rename(columns={label_col: "Label"})
        # Sobrescribir cualquier valor que no sea BENIGN
        non_benign = (df["Label"] != "BENIGN").sum()
        if non_benign > 0:
            print(f"  Corrigiendo {non_benign:,} filas con Label != BENIGN")
        df["Label"] = "BENIGN"

    # 3. Eliminar columnas completamente vacías
    empty_cols = df.columns[df.isna().all()].tolist()
    if empty_cols:
        print(f"  Eliminando {len(empty_cols)} columnas vacías: {empty_cols[:5]}...")
        df = df.drop(columns=empty_cols)

    # 4. Reemplazar infinitos por NaN (cicflowmeter genera inf en divisiones)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    if inf_count > 0:
        print(f"  Reemplazando {inf_count:,} valores infinitos por NaN")
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # 5. Eliminar filas con NaN en columnas numéricas
    before = len(df)
    df = df.dropna(subset=numeric_cols)
    dropped_nan = before - len(df)
    if dropped_nan > 0:
        print(f"  Eliminando {dropped_nan:,} filas con NaN ({dropped_nan/before*100:.1f}%)")

    # 6. Eliminar duplicados exactos
    before = len(df)
    df = df.drop_duplicates()
    dropped_dup = before - len(df)
    if dropped_dup > 0:
        print(f"  Eliminando {dropped_dup:,} duplicados exactos")

    # 7. Eliminar flows con duración 0 o negativa (flows corruptos)
    dur_col = None
    for candidate in ["Flow Duration", "flow_duration", "FlowDuration"]:
        if candidate in df.columns:
            dur_col = candidate
            break

    if dur_col:
        before = len(df)
        df = df[df[dur_col] > 0]
        dropped_dur = before - len(df)
        if dropped_dur > 0:
            print(f"  Eliminando {dropped_dur:,} flows con duración <= 0")

    # 8. Reset index
    df = df.reset_index(drop=True)

    total_dropped = original_len - len(df)
    print(f"\n  Original:  {original_len:,} filas")
    print(f"  Limpio:    {len(df):,} filas")
    print(f"  Descartado: {total_dropped:,} filas ({total_dropped/original_len*100:.1f}%)")

    return df


def validate(df: pd.DataFrame) -> bool:
    """Valida el dataset final."""
    print("\n─── Validación ─────────────────────────────────────")
    ok = True

    # Verificar columna Label
    assert "Label" in df.columns, "Falta columna Label"
    assert (df["Label"] == "BENIGN").all(), "Hay filas con Label != BENIGN"
    print(f"  Label: OK — todos son BENIGN")

    # Verificar no hay NaN ni inf
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    nan_count = df[numeric_cols].isna().sum().sum()
    inf_count = np.isinf(df[numeric_cols]).sum().sum()

    if nan_count == 0:
        print(f"  NaN: OK — ninguno")
    else:
        print(f"  NaN: ADVERTENCIA — {nan_count:,} valores")
        ok = False

    if inf_count == 0:
        print(f"  Infinitos: OK — ninguno")
    else:
        print(f"  Infinitos: ADVERTENCIA — {inf_count:,} valores")
        ok = False

    # Verificar cantidad de registros
    n = len(df)
    if n >= 40000:
        print(f"  Registros: OK — {n:,} (objetivo: ~45.000)")
    elif n >= 30000:
        print(f"  Registros: ADVERTENCIA — {n:,} (recomendado: ~45.000, considera más sitios)")
    else:
        print(f"  Registros: INSUFICIENTE — {n:,} (necesitas más sitios o más tiempo)")
        ok = False

    # Mostrar columnas
    print(f"  Columnas: {len(df.columns)} (esperado: ~{EXPECTED_COLS}+1 con Label)")

    # Muestra de estadísticas de las columnas numéricas clave
    key_cols = [c for c in ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                             "Flow Bytes/s", "Flow Packets/s"] if c in df.columns]
    if key_cols:
        print(f"\n  Estadísticas clave:")
        print(df[key_cols].describe().to_string())

    return ok


def main():
    parser = argparse.ArgumentParser(description="Limpia y valida el CSV benigno")
    parser.add_argument("--input", required=True, help="Archivo CSV o carpeta con CSVs")
    parser.add_argument("--output", default="benign_clean.csv", help="Archivo de salida")
    parser.add_argument("--sample", type=int, default=None,
                        help="Limitar a N filas aleatorias (para balanceo con dataset de ataques)")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    print("=" * 52)
    print("  CSV Benigno — Limpieza y Validación")
    print("=" * 52)

    # Cargar
    df = load_csvs(input_path)

    # Limpiar
    df = clean(df)

    # Muestrear si se pidió (para balancear con dataset de ataques)
    if args.sample and len(df) > args.sample:
        print(f"\nMuestreando {args.sample:,} filas aleatorias para balanceo...")
        df = df.sample(n=args.sample, random_state=42).reset_index(drop=True)

    # Validar
    valid = validate(df)

    # Guardar
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    size_mb = output_path.stat().st_size / (1024 * 1024)

    print(f"\n─── Resultado ───────────────────────────────────────")
    print(f"  Guardado en: {output_path}")
    print(f"  Tamaño:      {size_mb:.1f} MB")
    print(f"  Filas:       {len(df):,}")
    print(f"  Columnas:    {len(df.columns)}")
    print(f"  Estado:      {'LISTO PARA MERGE' if valid else 'REVISAR ADVERTENCIAS'}")
    print("=" * 52)

    if not valid:
        sys.exit(1)


if __name__ == "__main__":
    main()
