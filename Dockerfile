FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ─── Sistema base ─────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    wget \
    curl \
    git \
    libpcap0.8 \
    libpcap-dev \
    procps \
    psmisc \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ─── Dar capabilities al binario tcpdump ──────────────────
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# ─── Python + dependencias ────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Instalar cicflowmeter desde GitHub (requiere Python 3.12) ──
RUN pip install --no-cache-dir git+https://github.com/hieulw/cicflowmeter.git

# ─── Fix bug numpy.int64 → Decimal ────────────────────────
# numpy.mean/std/max/min retornan numpy.int64 que no es
# compatible con scapy EDecimal. Fix: castear a float().
RUN python -c "\
import cicflowmeter.utils as u; \
import inspect, pathlib; \
f = pathlib.Path(inspect.getfile(u)); \
txt = f.read_text(); \
fixes = [ \
  ('iat[\"mean\"] = numpy.mean(alist)', 'iat[\"mean\"] = float(numpy.mean(alist))'), \
  ('iat[\"std\"] = numpy.std(alist)',   'iat[\"std\"] = float(numpy.std(alist))'), \
  ('iat[\"max\"] = numpy.max(alist)',   'iat[\"max\"] = float(numpy.max(alist))'), \
  ('iat[\"min\"] = numpy.min(alist)',   'iat[\"min\"] = float(numpy.min(alist))'), \
]; \
[txt := txt.replace(a, b) for a, b in fixes]; \
f.write_text(txt); \
print('fix aplicado a:', f) \
"

# ─── Verificar instalación ─────────────────────────────────
RUN cicflowmeter --help > /dev/null 2>&1 && echo "cicflowmeter OK"

# ─── Crear estructura de carpetas ─────────────────────────
RUN mkdir -p /app/captures /app/csv_output

# ─── Código de la aplicación ──────────────────────────────
COPY app/ ./app/
COPY urls.txt ./urls.txt

# ─── Permisos ─────────────────────────────────────────────
RUN groupadd -r capture && \
    useradd -r -g capture -s /bin/false capture && \
    usermod -aG root capture && \
    chown -R capture:capture /app/captures /app/csv_output

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
USER root

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
