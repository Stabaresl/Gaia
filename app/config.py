"""
Configuración centralizada para captura de tráfico benigno.

CAMBIOS v2.2:
- TOTAL_SECONDS=4200 (70 min) para 28 sitios con ~150s/sitio promedio
- MIN_PER_SITE=120s, MAX_PER_SITE=180s — rango correcto para 28 sitios
- El rango [120*28=56min, 180*28=84min] contiene 70min → distribute_time() funciona
- Más workers y batch más grande para mayor densidad
"""

import os
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class CaptureConfig:

    # ─── Tiempos ────────────────────────────────────────────────────────────
    # Con 28 sitios: MIN*28=56min ≤ TOTAL=70min ≤ MAX*28=84min ✅
    TOTAL_SECONDS: int = 10320          # 129 minutos total
    MIN_PER_SITE: int = 150            # Mínimo 2 min por sitio
    MAX_PER_SITE: int = 240            # Máximo 3 min por sitio

    # ─── tcpdump ────────────────────────────────────────────────────────────
    SNAPLEN: int = 65535
    TIMESTAMP_PRECISION: str = "nano"

    # ─── Wget / HTTP ─────────────────────────────────────────────────────────
    WGET_TIMEOUT: int = 30
    WGET_TOTAL_TIMEOUT: int = 150      # 2.5 min para wget recursivo
    WGET_RATE_LIMIT: str = "0"         # SIN límite
    WGET_RETRIES: int = 3

    # ─── Paralelismo ────────────────────────────────────────────────────────
    MAX_PARALLEL_WORKERS: int = 8
    PARALLEL_BATCH_SIZE: int = 12

    # ─── DNS ────────────────────────────────────────────────────────────────
    DNS_QUERIES_MIN: int = 15
    DNS_QUERIES_MAX: int = 35
    DNS_DELAY_MIN: float = 0.01
    DNS_DELAY_MAX: float = 0.05

    # ─── Etiquetas ML ───────────────────────────────────────────────────────
    LABEL_BENIGN: str = "BENIGN"
    LABEL_ATTACK: str = "ATTACK"

    # ─── User-Agents rotados ─────────────────────────────────────────────────
    USER_AGENTS: Tuple[str, ...] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    )

    # ─── Subdominios DNS ────────────────────────────────────────────────────
    DNS_SUBDOMAINS: Tuple[str, ...] = (
        "", "www", "mail", "ftp", "api", "cdn", "static",
        "img", "assets", "media", "login", "auth", "blog",
        "fonts", "analytics", "js", "css", "api-v2",
        "graphql", "img2", "static1", "static2", "ws",
        "download", "files", "secure", "docs", "help",
    )

    # ─── Recursos pesados a descargar ────────────────────────────────────────
    HEAVY_RESOURCES: Tuple[str, ...] = (
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/favicon.ico",
        "/manifest.json",
        "/sw.js",
        "/service-worker.js",
        "/.well-known/security.txt",
        "/atom.xml",
        "/rss.xml",
        "/feed.xml",
        "/humans.txt",
    )

    @property
    def interface(self) -> str:
        return os.getenv("CAPTURE_INTERFACE", "eth0")

    @property
    def snaplen_str(self) -> str:
        return str(self.SNAPLEN)


CONFIG = CaptureConfig()
