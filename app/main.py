"""
API FastAPI para orquestación de capturas de tráfico benigno.
Diseñado para integración con n8n y pipelines ML de detección DDoS.

CAMBIOS v2.3:
- Jobs de conversión y limpieza ahora se persisten en disco (/app/csv_output/jobs/).
  Si el servidor se reinicia, los jobs se recuperan automáticamente.
- Jobs que estaban en "running" al reiniciar se marcan como "failed" con mensaje
  explicativo, para que n8n pueda relanzarlos.
- Semáforo: máximo 2 conversiones cicflowmeter simultáneas para no saturar CPU
  ni provocar que el healthcheck falle.
- /clean ASÍNCRONO (v2.2): retorna job_id inmediatamente, procesa en background.
- /convert ASÍNCRONO (v2.1): retorna job_id inmediatamente, procesa en background.
"""

import os
import subprocess
import shutil
import random
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from enum import Enum

import numpy as np
import pandas as pd

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .config import CONFIG
from .capture import (
    TcpdumpManager,
    get_default_interface,
    resolve_domain,
    resolve_domain_multi,
    TcpdumpCaptureError,
)
from .traffic_generator import TrafficGenerator


app = FastAPI(
    title="TCPDump Capture API",
    description="API para captura de tráfico de red benigno con tcpdump. "
                "Genera archivos PCAP compatibles con CICFlowMeter.",
    version="2.3.0"
)


# ─── Configuración ──────────────────────────────────────────────────────────

CSV_BASE_DIR = Path("/app/csv_output")
JOBS_DIR = CSV_BASE_DIR / "jobs"          # directorio donde se persisten los jobs
JOBS_DIR.mkdir(parents=True, exist_ok=True)

# Semáforo: máximo 2 conversiones cicflowmeter simultáneas
CICFLOW_SEMAPHORE = threading.Semaphore(2)


# ─── Estado global (se carga desde disco al arrancar) ───────────────────────

jobs: Dict[str, Dict[str, Any]] = {}
clean_jobs: Dict[str, Dict[str, Any]] = {}


class JobStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    PARTIAL   = "partial"


# ─── Persistencia de jobs en disco ──────────────────────────────────────────

def _job_path(job_id: str, prefix: str = "conv") -> Path:
    """Ruta del archivo JSON de un job."""
    safe_id = job_id.replace("/", "_").replace("\\", "_")
    return JOBS_DIR / f"{prefix}__{safe_id}.json"


def _save_job(job: Dict[str, Any], prefix: str = "conv"):
    """Guarda el estado del job en disco (sobrescribe). Escritura atómica."""
    try:
        path = _job_path(job["job_id"], prefix)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(job, default=str), encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        print(f"[WARN] No se pudo guardar job {job.get('job_id')}: {e}")


def _load_all_jobs():
    """
    Carga todos los jobs del disco al arrancar el servidor.
    Jobs que estaban en 'running' o 'pending' se marcan como 'failed'
    porque sus threads ya no existen tras el reinicio.
    """
    global jobs, clean_jobs
    for path in JOBS_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            job_id = data.get("job_id", "")
            prefix = "clean" if path.name.startswith("clean__") else "conv"

            # Si estaba corriendo, el thread murió → marcar failed
            if data.get("status") in ("pending", "running"):
                data["status"] = "failed"
                data["error"] = (
                    "El servidor se reinició mientras este job estaba en ejecución. "
                    "Vuelve a lanzarlo desde n8n."
                )
                data["finished_at"] = datetime.utcnow().isoformat()
                _save_job(data, prefix)

            if prefix == "clean":
                clean_jobs[job_id] = data
            else:
                jobs[job_id] = data
        except Exception as e:
            print(f"[WARN] No se pudo cargar job desde {path}: {e}")

    total = len(jobs) + len(clean_jobs)
    print(f"[STARTUP] {total} jobs cargados desde disco "
          f"({len(jobs)} conversión, {len(clean_jobs)} limpieza)")


# Cargar jobs al importar el módulo
_load_all_jobs()


# ─── Modelos Pydantic ────────────────────────────────────────────────────────

class CaptureConfigResponse(BaseModel):
    total_seconds: int
    total_minutos: float
    min_per_site: int
    max_per_site: int
    snaplen: int
    timestamp_precision: str
    user_agents_available: int
    interface: str


class CaptureResult(BaseModel):
    domain: str
    ip: str
    extra_ips: List[str] = []
    interface: str
    snaplen: int
    file: str
    capture_start: str
    capture_end: str
    duration_seconds: float
    requests_http: int
    queries_dns: int
    size_bytes: int
    size_mb: float
    traffic_generated: bool
    has_packets: bool
    packets_count: int
    label: str


class SessionResult(BaseModel):
    timestamp: str
    sesion_dir: str
    duracion_total_segundos: int
    label_sesion: str
    exitosos: int
    fallidos: int
    total_mb: float
    capturas: List[CaptureResult]
    errores: List[Dict[str, Any]]


class FilesListResponse(BaseModel):
    sessions: Dict[str, Any]


# ─── Modelos para conversión ─────────────────────────────────────────────────

class ConversionRequest(BaseModel):
    session_id: str
    pcap_file: str
    output_label: str = "BENIGN"
    combine_outputs: bool = True


class ConversionJobResponse(BaseModel):
    job_id: str
    session_id: str
    pcap_file: str
    status: str
    message: str


class ConversionResult(BaseModel):
    domain: str
    pcap_file: str
    status: str
    csv_files: List[str] = []
    error_message: Optional[str] = None
    records_count: int = 0


# ─── Modelos para limpieza ──────────────────────────────────────────────────

class CleanRequest(BaseModel):
    session_id: str
    sample: int = 0
    output_filename: str = "benign_clean.csv"


class CleanJobResponse(BaseModel):
    job_id: str
    session_id: str
    status: str
    message: str


class CleanResponse(BaseModel):
    status: str
    output_file: str
    rows: int
    columns: int
    size_mb: float
    rows_before: int
    dropped_nan: int
    dropped_duplicates: int
    dropped_zero_duration: int
    dropped_by_sample: int
    processing_time_seconds: float
    warnings: List[str] = []


# ─── Funciones Auxiliares ───────────────────────────────────────────────────

def get_output_dir() -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"/app/captures/{timestamp}"
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def distribute_time(n_urls: int, total: int, min_t: int, max_t: int) -> List[float]:
    if n_urls == 0:
        return []
    times = [random.uniform(min_t, max_t) for _ in range(n_urls)]
    current_sum = sum(times)
    factor = total / current_sum
    times = [t * factor for t in times]
    times = [max(min_t, min(max_t, t)) for t in times]
    diff = total - sum(times)
    if abs(diff) > 0.1:
        candidates = [i for i, t in enumerate(times) if t + diff / n_urls <= max_t]
        if candidates:
            idx = random.choice(candidates)
            times[idx] += diff
    random.shuffle(times)
    return [round(t, 1) for t in times]


def load_urls() -> List[str]:
    urls_file = Path("/app/urls.txt")
    if not urls_file.exists():
        raise HTTPException(status_code=500, detail="Archivo urls.txt no encontrado")
    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not urls:
        raise HTTPException(status_code=500, detail="No hay URLs válidas en urls.txt")
    return urls


def extract_domain(url: str) -> str:
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split(":")[0]


# ─── Funciones de conversión ────────────────────────────────────────────────

def run_cicflowmeter(pcap_path: Path, output_dir: Path) -> Dict[str, Any]:
    if not pcap_path.exists():
        return {"status": "error", "error": f"PCAP no existe: {pcap_path}", "files": []}

    output_dir.mkdir(parents=True, exist_ok=True)
    output_csv = output_dir / f"{pcap_path.stem}.csv"

    try:
        cmd = ["cicflowmeter", "-f", str(pcap_path), "-c", str(output_csv)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            return {
                "status": "error",
                "error": result.stderr or "cicflowmeter retornó código no-cero",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "files": []
            }

        generated_files = list(output_dir.glob("*.csv"))
        if not generated_files:
            return {
                "status": "error",
                "error": "No se generaron archivos CSV",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "files": []
            }

        return {
            "status": "success",
            "files": [f.name for f in generated_files],
            "file_paths": [str(f) for f in generated_files],
            "stdout": result.stdout[-500:] if result.stdout else "",
            "records": _count_csv_records(generated_files[0])
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Timeout: cicflowmeter tardó más de 5 minutos", "files": []}
    except FileNotFoundError:
        return {"status": "error", "error": "cicflowmeter no encontrado", "files": []}
    except Exception as e:
        return {"status": "error", "error": str(e), "files": []}


def _count_csv_records(csv_path: Path) -> int:
    try:
        with open(csv_path, 'r') as f:
            return sum(1 for _ in f) - 1
    except Exception:
        return 0


def _copy_to_combined(
    session_dir: Path,
    combined_dir: Path,
    domain: str,
    csv_files: List[Path]
) -> List[str]:
    combined_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for csv_file in csv_files:
        new_name = f"{session_dir.name}_{domain}_{csv_file.name}"
        dest = combined_dir / new_name
        shutil.copy2(csv_file, dest)
        copied.append(str(dest))
    return copied


# ─── Background worker para conversión ──────────────────────────────────────

def _run_conversion_job(
    job_id: str,
    pcap_path: Path,
    session_csv_dir: Path,
    combined_dir: Optional[Path],
    domain: str,
):
    """
    Ejecuta cicflowmeter en background thread.
    - Semáforo: máximo 2 simultáneos para no saturar CPU.
    - Estado persistido en disco en cada transición.
    """
    try:
        # Esperar turno (máx 2 simultáneos)
        CICFLOW_SEMAPHORE.acquire()
        try:
            jobs[job_id]["status"] = JobStatus.RUNNING
            jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
            _save_job(jobs[job_id], "conv")

            domain_csv_dir = session_csv_dir / domain
            domain_csv_dir.mkdir(parents=True, exist_ok=True)

            conversion = run_cicflowmeter(pcap_path, domain_csv_dir)

            if conversion["status"] == "success":
                csv_paths = [Path(p) for p in conversion.get("file_paths", [])]
                all_csv = []
                if combined_dir:
                    copied = _copy_to_combined(session_csv_dir, combined_dir, domain, csv_paths)
                    all_csv.extend(copied)
                else:
                    all_csv.extend(conversion.get("file_paths", []))

                jobs[job_id]["status"] = JobStatus.COMPLETED
                jobs[job_id]["csv_files"] = conversion.get("files", [])
                jobs[job_id]["all_csv_paths"] = all_csv
                jobs[job_id]["records_count"] = conversion.get("records", 0)
            else:
                jobs[job_id]["status"] = JobStatus.FAILED
                jobs[job_id]["error"] = conversion.get("error", "Unknown error")
                jobs[job_id]["csv_files"] = []

        finally:
            CICFLOW_SEMAPHORE.release()

    except Exception as e:
        jobs[job_id]["status"] = JobStatus.FAILED
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["csv_files"] = []
    finally:
        jobs[job_id]["finished_at"] = datetime.utcnow().isoformat()
        _save_job(jobs[job_id], "conv")


# ─── Funciones de limpieza ──────────────────────────────────────────────────

def _clean_dataframe(df: "pd.DataFrame", sample: int) -> Dict[str, Any]:
    rows_before = len(df)
    dropped_nan = 0
    dropped_duplicates = 0
    dropped_zero_duration = 0
    dropped_by_sample = 0
    warnings = []

    df.columns = df.columns.str.strip()

    label_col = next(
        (c for c in ["Label", "label", "LABEL", "class", "Class"] if c in df.columns), None
    )
    if label_col is None:
        warnings.append("Columna Label no encontrada — creada con valor BENIGN")
        df["Label"] = "BENIGN"
    else:
        if label_col != "Label":
            df = df.rename(columns={label_col: "Label"})
        non_benign = (df["Label"] != "BENIGN").sum()
        if non_benign > 0:
            warnings.append(f"{non_benign} filas tenían Label != BENIGN — corregidas")
        df["Label"] = "BENIGN"

    empty_cols = df.columns[df.isna().all()].tolist()
    if empty_cols:
        warnings.append(f"{len(empty_cols)} columnas completamente vacías eliminadas")
        df = df.drop(columns=empty_cols)

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    if inf_count > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df = df.dropna(subset=numeric_cols)
    dropped_nan = before - len(df)

    before = len(df)
    df = df.drop_duplicates()
    dropped_duplicates = before - len(df)

    dur_col = next(
        (c for c in ["Flow Duration", "flow_duration", "FlowDuration"] if c in df.columns), None
    )
    if dur_col:
        before = len(df)
        df = df[df[dur_col] > 0]
        dropped_zero_duration = before - len(df)
    else:
        warnings.append("Columna 'Flow Duration' no encontrada — no se filtraron flows de duración 0")

    if len(df) < 10000:
        warnings.append(f"Solo {len(df)} registros tras limpieza — considera más sitios o más tiempo")

    before_sample = len(df)
    if sample and len(df) > sample:
        df = df.sample(n=sample, random_state=42).reset_index(drop=True)
        dropped_by_sample = before_sample - len(df)
    else:
        df = df.reset_index(drop=True)

    return {
        "df": df,
        "rows_before": rows_before,
        "dropped_nan": dropped_nan,
        "dropped_duplicates": dropped_duplicates,
        "dropped_zero_duration": dropped_zero_duration,
        "dropped_by_sample": dropped_by_sample,
        "warnings": warnings,
    }


# ─── Background worker para limpieza ────────────────────────────────────────

def _run_clean_job(job_id: str, session_id: str, sample: int, output_filename: str):
    """Ejecuta limpieza en background thread. Estado persistido en disco."""
    try:
        clean_jobs[job_id]["status"] = "running"
        clean_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        _save_job(clean_jobs[job_id], "clean")

        start_time = time.time()
        combined_dir = CSV_BASE_DIR / "combined"
        session_csv_dir = CSV_BASE_DIR / session_id
        output_path = CSV_BASE_DIR / output_filename

        if combined_dir.exists() and any(combined_dir.rglob("*.csv")):
            search_dir = combined_dir
        elif session_csv_dir.exists() and any(session_csv_dir.rglob("*.csv")):
            search_dir = session_csv_dir
        else:
            raise ValueError(
                f"No se encontraron CSVs para sesión '{session_id}'. "
                f"Ejecuta /convert primero."
            )

        files = [f for f in sorted(search_dir.rglob("*.csv"))
                 if f.resolve() != output_path.resolve()]

        if not files:
            raise ValueError("No hay archivos CSV para limpiar")

        dfs, load_errors = [], []
        for f in files:
            try:
                df_tmp = pd.read_csv(f, low_memory=False)
                if len(df_tmp) > 0:
                    dfs.append(df_tmp)
            except Exception as e:
                load_errors.append(f"{f.name}: {e}")

        if not dfs:
            raise ValueError(f"Ningún CSV válido. Errores: {load_errors[:3]}")

        df = pd.concat(dfs, ignore_index=True)
        clean_result = _clean_dataframe(df, sample)
        df_clean = clean_result["df"]

        if len(df_clean) == 0:
            raise ValueError(
                "El DataFrame quedó vacío tras la limpieza. "
                "Revisa que los PCAPs tengan tráfico real."
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        df_clean.to_csv(output_path, index=False)
        size_mb = round(output_path.stat().st_size / (1024 * 1024), 2)

        if load_errors:
            clean_result["warnings"].extend([f"Error cargando {e}" for e in load_errors])

        clean_jobs[job_id].update({
            "status": "completed",
            "output_file": str(output_path),
            "rows": len(df_clean),
            "columns": len(df_clean.columns),
            "size_mb": size_mb,
            "rows_before": clean_result["rows_before"],
            "dropped_nan": clean_result["dropped_nan"],
            "dropped_duplicates": clean_result["dropped_duplicates"],
            "dropped_zero_duration": clean_result["dropped_zero_duration"],
            "dropped_by_sample": clean_result["dropped_by_sample"],
            "processing_time_seconds": round(time.time() - start_time, 2),
            "warnings": clean_result["warnings"],
        })

    except Exception as e:
        clean_jobs[job_id]["status"] = "failed"
        clean_jobs[job_id]["error"] = str(e)
    finally:
        clean_jobs[job_id]["finished_at"] = datetime.utcnow().isoformat()
        _save_job(clean_jobs[job_id], "clean")


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.3.0",
        "jobs_in_memory": len(jobs),
        "clean_jobs_in_memory": len(clean_jobs),
        "cicflow_slots_available": CICFLOW_SEMAPHORE._value,
    }


@app.get("/capture/config", response_model=CaptureConfigResponse)
def get_config():
    return CaptureConfigResponse(
        total_seconds=CONFIG.TOTAL_SECONDS,
        total_minutos=round(CONFIG.TOTAL_SECONDS / 60, 1),
        min_per_site=CONFIG.MIN_PER_SITE,
        max_per_site=CONFIG.MAX_PER_SITE,
        snaplen=CONFIG.SNAPLEN,
        timestamp_precision=CONFIG.TIMESTAMP_PRECISION,
        user_agents_available=len(CONFIG.USER_AGENTS),
        interface=get_default_interface()
    )


@app.get("/capture", response_model=SessionResult)
def start_capture_session():
    session_start = datetime.utcnow()
    output_dir = get_output_dir()
    urls = load_urls()

    n = len(urls)
    tiempos = distribute_time(n, CONFIG.TOTAL_SECONDS, CONFIG.MIN_PER_SITE, CONFIG.MAX_PER_SITE)

    resultados: List[CaptureResult] = []
    errores: List[Dict[str, Any]] = []

    for url, duracion in zip(urls, tiempos):
        domain = extract_domain(url)
        log_prefix = f"[{datetime.utcnow().strftime('%H:%M:%S')}] {domain}"
        print(f"{log_prefix} → {duracion}s | dir: {output_dir}")

        try:
            result = capture_single_domain(domain, url, duracion, output_dir)
            resultados.append(result)
        except Exception as e:
            print(f"{log_prefix} → ERROR: {e}")
            errores.append({
                "domain": domain,
                "url": url,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            })

    total_bytes = sum(r.size_bytes for r in resultados)

    return SessionResult(
        timestamp=session_start.isoformat(),
        sesion_dir=output_dir,
        duracion_total_segundos=CONFIG.TOTAL_SECONDS,
        label_sesion=CONFIG.LABEL_BENIGN,
        exitosos=len(resultados),
        fallidos=len(errores),
        total_mb=round(total_bytes / (1024 * 1024), 2),
        capturas=resultados,
        errores=errores
    )


def capture_single_domain(
    domain: str,
    url: str,
    duration_seconds: float,
    output_dir: str
) -> CaptureResult:
    try:
        all_ips = resolve_domain_multi(domain)
    except TcpdumpCaptureError as e:
        raise HTTPException(status_code=400, detail=str(e))

    primary_ip = all_ips[0]
    extra_ips = all_ips[1:] if len(all_ips) > 1 else []

    print(f"  [DNS] {domain} → {len(all_ips)} IPs: {all_ips[:5]}{'...' if len(all_ips) > 5 else ''}")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.pcap"
    output_file = os.path.join(output_dir, filename)
    iface = get_default_interface()
    tmp_dir = f"/tmp/wget_{domain}_{timestamp}_{os.getpid()}"

    capture_mgr = TcpdumpManager(iface, primary_ip, output_file, extra_ips=extra_ips)
    capture_start = datetime.utcnow().isoformat()

    try:
        capture_mgr.start()
    except TcpdumpCaptureError as e:
        raise HTTPException(status_code=500, detail=f"Fallo tcpdump: {e}")

    generator = TrafficGenerator(domain, url, tmp_dir)

    try:
        traffic_stats = generator.generate_session(duration_seconds)
    finally:
        generator.cleanup()

    stop_stats = capture_mgr.stop(timeout=10)  # noqa: F841
    capture_end = datetime.utcnow().isoformat()
    validation = capture_mgr.validate_capture()

    return CaptureResult(
        domain=domain,
        ip=primary_ip,
        extra_ips=extra_ips,
        interface=iface,
        snaplen=CONFIG.SNAPLEN,
        file=filename,
        capture_start=capture_start,
        capture_end=capture_end,
        duration_seconds=round(duration_seconds, 1),
        requests_http=traffic_stats["requests_http"],
        queries_dns=traffic_stats["queries_dns"],
        size_bytes=validation["file_size_bytes"],
        size_mb=validation.get("file_size_mb", 0),
        traffic_generated=traffic_stats["traffic_generated"],
        has_packets=validation["valid"],
        packets_count=validation.get("packets_count", 0),
        label=CONFIG.LABEL_BENIGN
    )


@app.get("/files", response_model=FilesListResponse)
def list_files():
    base = Path("/app/captures")
    sessions = {}
    if not base.exists():
        return FilesListResponse(sessions={})
    for session_dir in sorted(base.iterdir()):
        if not session_dir.is_dir():
            continue
        pcap_files = [f for f in session_dir.iterdir() if f.suffix == '.pcap']
        json_files = [f for f in session_dir.iterdir() if f.suffix == '.json']
        total_size = sum(f.stat().st_size for f in pcap_files)
        sessions[session_dir.name] = {
            "total_pcaps": len(pcap_files),
            "total_metadata": len(json_files),
            "total_mb": round(total_size / (1024 * 1024), 2),
            "pcaps": sorted([f.name for f in pcap_files]),
            "metadata": sorted([f.name for f in json_files])
        }
    return FilesListResponse(sessions=sessions)


@app.get("/files/{session_name}")
def get_session_details(session_name: str):
    session_path = Path(f"/app/captures/{session_name}")
    if not session_path.exists() or not session_path.is_dir():
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    metadata_file = session_path / "session_metadata.json"
    metadata = None
    if metadata_file.exists():
        with open(metadata_file) as f:
            metadata = json.load(f)
    pcaps = sorted([f.name for f in session_path.glob("*.pcap")])
    return {"session_name": session_name, "metadata": metadata, "pcaps": pcaps, "path": str(session_path)}


# ─── /convert ASÍNCRONO ──────────────────────────────────────────────────────

@app.post("/convert", response_model=ConversionJobResponse)
def convert_single_pcap(request: ConversionRequest):
    """
    ASÍNCRONO: convierte UN solo PCAP a CSV en background thread.
    Retorna inmediatamente con job_id.
    Estado persistido en disco — sobrevive reinicios del servidor.
    """
    session_pcap_dir = Path(f"/app/captures/{request.session_id}")
    if not session_pcap_dir.exists():
        raise HTTPException(status_code=404, detail=f"Sesión no encontrada: {request.session_id}")

    pcap_path = session_pcap_dir / request.pcap_file
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP no encontrado: {request.pcap_file}")

    session_csv_dir = CSV_BASE_DIR / request.session_id
    combined_dir = CSV_BASE_DIR / "combined" if request.combine_outputs else None
    session_csv_dir.mkdir(parents=True, exist_ok=True)

    domain = pcap_path.stem.split('_')[0].replace('.', '_')
    job_id = f"{request.session_id}__{request.pcap_file}"

    if job_id in jobs and jobs[job_id]["status"] in (JobStatus.RUNNING, JobStatus.COMPLETED):
        return ConversionJobResponse(
            job_id=job_id,
            session_id=request.session_id,
            pcap_file=request.pcap_file,
            status=jobs[job_id]["status"],
            message=f"Job ya existe con status: {jobs[job_id]['status']}"
        )

    job = {
        "job_id": job_id,
        "session_id": request.session_id,
        "pcap_file": request.pcap_file,
        "domain": domain,
        "status": JobStatus.PENDING,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "finished_at": None,
        "csv_files": [],
        "all_csv_paths": [],
        "records_count": 0,
        "error": None,
    }
    jobs[job_id] = job
    _save_job(job, "conv")

    thread = threading.Thread(
        target=_run_conversion_job,
        args=(job_id, pcap_path, session_csv_dir, combined_dir, domain),
        daemon=True
    )
    thread.start()

    return ConversionJobResponse(
        job_id=job_id,
        session_id=request.session_id,
        pcap_file=request.pcap_file,
        status=JobStatus.PENDING,
        message="Conversión iniciada en background. Usa GET /convert/status/{job_id} para verificar."
    )


@app.get("/convert/status/{job_id:path}")
def get_job_status(job_id: str):
    """Estado de un job de conversión. pending | running | completed | failed"""
    if job_id in jobs:
        return jobs[job_id]
    # Fallback: buscar en disco
    path = _job_path(job_id, "conv")
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        jobs[job_id] = data
        return data
    raise HTTPException(status_code=404, detail=f"Job no encontrado: {job_id}")


@app.get("/convert/jobs")
def list_jobs():
    return {
        "total": len(jobs),
        "by_status": {
            status: sum(1 for j in jobs.values() if j["status"] == status)
            for status in [JobStatus.PENDING, JobStatus.RUNNING, JobStatus.COMPLETED, JobStatus.FAILED]
        },
        "jobs": list(jobs.values())
    }


# ─── /clean ASÍNCRONO ────────────────────────────────────────────────────────

@app.post("/clean", response_model=CleanJobResponse)
def clean_csv(request: CleanRequest):
    """
    ASÍNCRONO: limpia el CSV benigno en background thread.
    Retorna inmediatamente con job_id.
    Estado persistido en disco — sobrevive reinicios del servidor.

    Flujo en n8n:
      POST /clean → recibe job_id
      Wait (30s)
      GET /clean/status/{job_id}
      If completed → continuar | If running → volver al Wait | If failed → error
    """
    job_id = f"{request.session_id}__clean__{request.output_filename}"

    if job_id in clean_jobs and clean_jobs[job_id]["status"] in ("running", "completed"):
        return CleanJobResponse(
            job_id=job_id,
            session_id=request.session_id,
            status=clean_jobs[job_id]["status"],
            message=f"Job ya existe con status: {clean_jobs[job_id]['status']}"
        )

    job = {
        "job_id": job_id,
        "session_id": request.session_id,
        "output_filename": request.output_filename,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "finished_at": None,
        "error": None,
    }
    clean_jobs[job_id] = job
    _save_job(job, "clean")

    thread = threading.Thread(
        target=_run_clean_job,
        args=(job_id, request.session_id, request.sample, request.output_filename),
        daemon=True
    )
    thread.start()

    return CleanJobResponse(
        job_id=job_id,
        session_id=request.session_id,
        status="pending",
        message="Limpieza iniciada en background. Usa GET /clean/status/{job_id} para verificar."
    )


@app.get("/clean/status/{job_id:path}")
def get_clean_status(job_id: str):
    """Estado de un job de limpieza. pending | running | completed | failed"""
    if job_id in clean_jobs:
        return clean_jobs[job_id]
    # Fallback: buscar en disco
    path = _job_path(job_id, "clean")
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        clean_jobs[job_id] = data
        return data
    raise HTTPException(status_code=404, detail=f"Job no encontrado: {job_id}")


@app.get("/clean/jobs")
def list_clean_jobs():
    return {
        "total": len(clean_jobs),
        "by_status": {
            status: sum(1 for j in clean_jobs.values() if j["status"] == status)
            for status in ["pending", "running", "completed", "failed"]
        },
        "jobs": list(clean_jobs.values())
    }
