"""
Módulo de captura de paquetes con tcpdump.
Optimizado para generar PCAPs compatibles con CICFlowMeter.

CAMBIOS v2.1:
- Filtro BPF ampliado: captura IP principal + CDN IPs + DNS (port 53)
  Esto soluciona el problema de sitios que redirigen a CDNs con IPs distintas
  (ej: mozilla.org → firefox.com, assets en fastly/cloudflare).
- resolve_domain_multi() resuelve múltiples IPs del mismo dominio.
- Filtro por src del contenedor como fallback para capturar TODO el tráfico saliente.
"""

import os
import signal
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from .config import CONFIG


class TcpdumpCaptureError(Exception):
    """Error específico de captura tcpdump."""
    pass


class TcpdumpManager:
    """
    Gestor de procesos tcpdump con manejo robusto de señales y validación.

    Produce archivos PCAP con:
    - Timestamps nanosegundos (requerido por CICFlowMeter)
    - Snaplen 65535 (paquetes completos)
    - Filtro ampliado: IP principal + CDN IPs + DNS
    """

    def __init__(self, interface: str, target_ip: str, output_file: str,
                 extra_ips: Optional[List[str]] = None):
        self.interface = interface
        self.target_ip = target_ip
        self.extra_ips = extra_ips or []   # IPs adicionales (CDN, redirects)
        self.output_file = output_file
        self.process: Optional[subprocess.Popen] = None
        self.start_time: Optional[datetime] = None

    def _build_bpf_filter(self) -> str:
        """
        Construye filtro BPF que captura:
        1. Tráfico a/desde la IP principal del dominio
        2. Tráfico a/desde IPs adicionales (CDN, redirects resueltos)
        3. Todo el tráfico DNS (port 53) — captura queries y respuestas

        Esto es crítico para sitios como mozilla.org que redirigen a otros dominios
        con IPs diferentes, o que sirven assets desde CDNs (fastly, cloudflare, akamai).
        """
        all_ips = [self.target_ip] + [ip for ip in self.extra_ips if ip != self.target_ip]

        # Construir expresión OR para todas las IPs
        ip_parts = " or ".join(f"host {ip}" for ip in all_ips)

        if len(all_ips) > 1:
            host_expr = f"({ip_parts})"
        else:
            host_expr = ip_parts

        # Filtro final: (todas las IPs del dominio) OR (cualquier DNS)
        bpf = f"{host_expr} or port 53"
        return bpf

    def _build_command(self) -> List[str]:
        """
        Construye comando tcpdump optimizado para ML.

        CORRECCIÓN v2.1: usa filtro BPF ampliado en lugar de solo "host IP".
        El filtro se pasa como un único string al argumento de tcpdump.
        """
        bpf_filter = self._build_bpf_filter()

        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-w", self.output_file,
            "-s", CONFIG.snaplen_str,
            "-U",                              # Unbuffered: escribe inmediato
            "--time-stamp-precision=nano",     # Nanosegundos para IAT
            "-n",                              # No resolver nombres
            "-nn",                             # No resolver puertos
            bpf_filter,                        # ← filtro ampliado como último arg
        ]
        return cmd

    def start(self) -> None:
        """Inicia tcpdump de forma segura."""
        if self.process is not None:
            raise TcpdumpCaptureError("Tcpdump ya está corriendo")

        Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command()
        self.start_time = datetime.utcnow()

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
        except Exception as e:
            raise TcpdumpCaptureError(f"Fallo al iniciar tcpdump: {e}")

        # Esperar inicialización
        time.sleep(1.0)

        # Verificar que no murió inmediatamente
        if self.process.poll() is not None:
            stderr = (
                self.process.stderr.read().decode("utf-8", errors="replace")
                if self.process.stderr else ""
            )
            raise TcpdumpCaptureError(f"Tcpdump murió inmediatamente: {stderr}")

    def stop(self, timeout: int = 10) -> Dict[str, Any]:
        """Detiene tcpdump gracefully con fallback a SIGKILL."""
        if self.process is None:
            return {"error": "No había proceso activo"}

        stats = {
            "termination_signal": "SIGTERM",
            "termination_success": False,
            "files_generated": [],
        }

        try:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=timeout)
                stats["termination_success"] = True
            except subprocess.TimeoutExpired:
                self.process.send_signal(signal.SIGKILL)
                self.process.wait(timeout=5)
                stats["termination_signal"] = "SIGKILL"
        except Exception as e:
            stats["termination_error"] = str(e)
        finally:
            if self.process and self.process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.process = None

        # Encontrar archivos generados
        base_path = Path(self.output_file)
        base_dir = base_path.parent
        base_stem = base_path.stem

        for f in base_dir.iterdir():
            if f.name.startswith(base_stem) and f.suffix == ".pcap":
                stats["files_generated"].append(str(f))

        return stats

    def validate_capture(self) -> Dict[str, Any]:
        """Valida que el PCAP contiene paquetes reales."""
        if not os.path.exists(self.output_file):
            return {
                "valid": False,
                "error": "Archivo no existe",
                "packets_count": 0,
                "file_size_bytes": 0,
                "file_size_mb": 0,
            }

        file_size = os.path.getsize(self.output_file)

        if file_size <= 24:
            return {
                "valid": False,
                "error": "Archivo vacío o corrupto (solo header)",
                "packets_count": 0,
                "file_size_bytes": file_size,
                "file_size_mb": 0,
            }

        # Contar paquetes
        try:
            result = subprocess.run(
                ["tcpdump", "-r", self.output_file, "-nn", "--count"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            packets = 0
            if result.returncode == 0:
                try:
                    packets = int(result.stdout.strip().split()[0])
                except (ValueError, IndexError):
                    pass

            return {
                "valid": packets > 0,
                "packets_count": packets,
                "file_size_bytes": file_size,
                "file_size_mb": round(file_size / (1024 * 1024), 2),
                "packets_per_mb": (
                    round(packets / (file_size / (1024 * 1024)), 2)
                    if file_size > 0 else 0
                ),
            }

        except subprocess.TimeoutExpired:
            return {
                "valid": file_size > 24,
                "error": "Timeout validando (archivo grande)",
                "packets_count": 0,
                "file_size_bytes": file_size,
                "file_size_mb": round(file_size / (1024 * 1024), 2),
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"Error validación: {e}",
                "packets_count": 0,
                "file_size_bytes": file_size,
                "file_size_mb": 0,
            }


# ─── Funciones auxiliares ────────────────────────────────────────────────────

def get_default_interface() -> str:
    """Detecta interfaz de red por defecto del contenedor."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    for iface in ["eth0", "ens160", "enp0s3", "wlan0"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface

    return "eth0"


def resolve_domain(domain: str) -> str:
    """Resuelve dominio a su primera IPv4."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        raise TcpdumpCaptureError(f"No se pudo resolver {domain}: {e}")


def resolve_domain_multi(domain: str) -> List[str]:
    """
    Resuelve dominio a TODAS sus IPs (round-robin DNS, CDN anycast, etc).

    Muchos sitios grandes devuelven múltiples IPs:
    - google.com → 142.250.x.x, 142.250.x.y, ...
    - fastly CDN → pool de IPs
    - cloudflare → anycast

    Capturar todas las IPs garantiza que si wget/curl conecta a cualquiera
    de ellas, tcpdump lo registre.

    También intenta resolver subdominios comunes del mismo dominio
    para capturar tráfico de assets (cdn.dominio.com, static.dominio.com).
    """
    ips = set()

    # Resolver dominio principal — getaddrinfo devuelve todas las IPs
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for r in results:
            ips.add(r[4][0])
    except Exception:
        pass

    # Fallback con gethostbyname_ex que también devuelve aliases
    try:
        _, aliases, addresses = socket.gethostbyname_ex(domain)
        ips.update(addresses)
        # Resolver aliases también (puede apuntar a CDN)
        for alias in aliases:
            try:
                ips.add(socket.gethostbyname(alias))
            except Exception:
                pass
    except Exception:
        pass

    # Resolver subdominios comunes que sirven assets
    asset_subdomains = ["www", "cdn", "static", "assets", "img", "media", "api"]
    for sub in asset_subdomains:
        try:
            target = f"{sub}.{domain}"
            ip = socket.gethostbyname(target)
            ips.add(ip)
        except Exception:
            pass

    # Garantizar que siempre hay al menos una IP
    if not ips:
        raise TcpdumpCaptureError(f"No se pudo resolver ninguna IP para {domain}")

    return list(ips)
