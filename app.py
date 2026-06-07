from fastapi import FastAPI
import subprocess, socket, os, time, random
from datetime import datetime
import urllib.request

app = FastAPI()

# ─── PARÁMETROS PERSONALIZABLES ───────────────────────────────
TOTAL_SECONDS = 2400      # 40 minutos
MIN_PER_SITE  = 30
MAX_PER_SITE  = 300
DNS_QUERIES_PER_SITE = 20
# ──────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

def get_output_dir():
    """Crea carpeta con fecha y hora de inicio de sesión"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"/app/captures/{timestamp}"
    os.makedirs(path, exist_ok=True)
    return path

def get_interface():
    result = subprocess.run(
        "ip route | grep default | awk '{print $5}' | head -1",
        shell=True, capture_output=True, text=True
    )
    iface = result.stdout.strip()
    return iface if iface else "eth0"

def distribute_time(n_urls, total, min_t, max_t):
    times = [random.uniform(min_t, max_t) for _ in range(n_urls)]
    factor = total / sum(times)
    times = [max(min_t, min(max_t, t * factor)) for t in times]
    diff = total - sum(times)
    times[random.randint(0, n_urls - 1)] += diff
    random.shuffle(times)
    return [round(t, 1) for t in times]

def generate_dns_queries(domain, count):
    subdomains = [
        "", "www", "mail", "ftp", "api", "cdn", "static",
        "img", "assets", "media", "login", "auth", "blog"
    ]
    for _ in range(count):
        sub = random.choice(subdomains)
        target = f"{sub}.{domain}" if sub else domain
        try:
            socket.gethostbyname(target)
        except Exception:
            pass
        time.sleep(random.uniform(0.1, 0.5))

def capture_domain(domain, url, duration_seconds, output_dir):
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"domain": domain, "error": f"DNS failed: {e}"}

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.pcap"
    output_file = os.path.join(output_dir, filename)
    iface = get_interface()
    tmp_dir = f"/tmp/wget_{domain}_{timestamp}"
    os.makedirs(tmp_dir, exist_ok=True)

    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, f"host {ip}", "-w", output_file, "-U"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(1)

    end_time = time.time() + duration_seconds - 1
    traffic_ok = False
    request_count = 0
    dns_count = 0

    while time.time() < end_time:
        try:
            wget_cmd = [
                "wget",
                "--recursive",
                "--level=1",
                "--page-requisites",
                "--no-check-certificate",
                "--quiet",
                "--timeout=10",
                "--tries=1",
                "--delete-after",
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "-P", tmp_dir,
                url
            ]
            subprocess.run(wget_cmd, timeout=15, capture_output=True)
            traffic_ok = True
            request_count += 1
        except Exception:
            pass

        dns_batch = random.randint(2, 6)
        generate_dns_queries(domain, dns_batch)
        dns_count += dns_batch

        pause = random.uniform(3, 10)
        if time.time() + pause < end_time:
            time.sleep(pause)
        else:
            break

    subprocess.run(["rm", "-rf", tmp_dir])
    proc.terminate()
    proc.wait()

    size = os.path.getsize(output_file)

    return {
        "domain": domain,
        "ip": ip,
        "interface": iface,
        "file": filename,
        "duration_seconds": duration_seconds,
        "requests_http": request_count,
        "queries_dns": dns_count,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "traffic_generated": traffic_ok,
        "has_packets": size > 24
    }

@app.get("/capture")
def capture():
    timestamp = datetime.utcnow().isoformat()
    output_dir = get_output_dir()   # ← carpeta nueva por sesión

    with open("/app/urls.txt", "r") as f:
        urls = [u.strip() for u in f if u.strip()]

    n = len(urls)
    tiempos = distribute_time(n, TOTAL_SECONDS, MIN_PER_SITE, MAX_PER_SITE)

    resultados = []
    errores = []

    for url, duracion in zip(urls, tiempos):
        domain = url.replace("https://","").replace("http://","").split("/")[0]
        print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Capturando {domain} por {duracion}s → {output_dir}")
        result = capture_domain(domain, url, duracion, output_dir)

        if "error" in result:
            errores.append(result)
        else:
            resultados.append(result)

    return {
        "timestamp": timestamp,
        "sesion_dir": output_dir,
        "duracion_total_segundos": TOTAL_SECONDS,
        "exitosos": len(resultados),
        "fallidos": len(errores),
        "total_mb": round(sum(r.get("size_bytes", 0) for r in resultados) / (1024*1024), 2),
        "capturas": resultados,
        "errores": errores
    }

@app.get("/capture/config")
def get_config():
    return {
        "total_seconds": TOTAL_SECONDS,
        "total_minutos": round(TOTAL_SECONDS / 60, 1),
        "min_per_site": MIN_PER_SITE,
        "max_per_site": MAX_PER_SITE,
        "dns_queries_per_site": DNS_QUERIES_PER_SITE,
    }

@app.get("/files")
def list_files():
    result = {}
    base = "/app/captures"
    for session in sorted(os.listdir(base)):
        session_path = os.path.join(base, session)
        if os.path.isdir(session_path):
            files = os.listdir(session_path)
            result[session] = {
                "total_archivos": len(files),
                "total_mb": round(sum(
                    os.path.getsize(os.path.join(session_path, f))
                    for f in files
                ) / (1024*1024), 2),
                "archivos": sorted(files)
            }
    return result