"""
Generador de tráfico benigno de alto volumen.
Objetivo: PCAPs >= 10 MB por sitio para datasets ML.

CAMBIOS v2.2:
- Soporte completo para 43 dominios (15 nuevos añadidos):
  w3schools, geeksforgeeks, httpd.apache, postgresql, mysql, redis,
  elastic, grafana, prometheus, ansible, kubernetes, docs.docker,
  rust-lang, go.dev, nodejs
"""

import os
import random
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List

from .config import CONFIG


class TrafficGenerator:

    def __init__(self, domain: str, url: str, tmp_dir: str):
        self.domain = domain
        self.url = url
        self.tmp_dir = tmp_dir
        self._ensure_tmp()

    def _ensure_tmp(self) -> None:
        Path(self.tmp_dir).mkdir(parents=True, exist_ok=True)

    def cleanup(self) -> None:
        try:
            if os.path.exists(self.tmp_dir):
                shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    # ─── DNS ────────────────────────────────────────────────────────────────

    def _dns_query(self, target: str) -> None:
        try:
            socket.gethostbyname(target)
        except Exception:
            pass

    def _generate_dns_burst(self, count: int) -> int:
        done = 0
        for _ in range(count):
            sub = random.choice(CONFIG.DNS_SUBDOMAINS)
            target = f"{sub}.{self.domain}" if sub else self.domain
            self._dns_query(target)
            done += 1
            time.sleep(random.uniform(CONFIG.DNS_DELAY_MIN, CONFIG.DNS_DELAY_MAX))
        return done

    # ─── HTTP con wget ────────────────────────────────────────────────────────

    def _wget_recursive(self, level: int = 3) -> bool:
        ua = random.choice(CONFIG.USER_AGENTS)
        cmd = [
            "wget",
            "--recursive",
            f"--level={level}",
            "--page-requisites",
            "--span-hosts",
            "--no-check-certificate",
            "--quiet",
            f"--timeout={CONFIG.WGET_TIMEOUT}",
            f"--tries={CONFIG.WGET_RETRIES}",
            "--delete-after",
            "--no-host-directories",
            "--reject=exe,zip,tar,gz,iso,dmg,pkg,deb,rpm,mp4,avi,mkv",
            f"--user-agent={ua}",
            "--header=Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "--header=Accept-Language: en-US,en;q=0.5",
            "--header=Accept-Encoding: gzip, deflate",
            "--header=Connection: keep-alive",
            "--header=Cache-Control: no-cache",
            "-P", self.tmp_dir,
            self.url,
        ]
        try:
            subprocess.run(cmd, timeout=CONFIG.WGET_TOTAL_TIMEOUT, capture_output=True)
            return True
        except Exception:
            return False

    def _wget_simple(self, url: str) -> bool:
        ua = random.choice(CONFIG.USER_AGENTS)
        cmd = [
            "wget",
            "--no-check-certificate",
            "--quiet",
            f"--timeout={CONFIG.WGET_TIMEOUT}",
            "--tries=1",
            "--delete-after",
            f"--user-agent={ua}",
            "-P", self.tmp_dir,
            url,
        ]
        try:
            subprocess.run(cmd, timeout=30, capture_output=True)
            return True
        except Exception:
            return False

    def _curl_request(self, url: str) -> bool:
        ua = random.choice(CONFIG.USER_AGENTS)
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-L",
            "--max-time", "20", "--retry", "1", "--compressed",
            "-H", f"User-Agent: {ua}",
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.5",
            "-H", "Accept-Encoding: gzip, deflate, br",
            "-H", "Connection: keep-alive",
            "-H", "Cache-Control: no-cache",
            "--insecure", url,
        ]
        try:
            subprocess.run(cmd, timeout=25, capture_output=True)
            return True
        except Exception:
            return False

    def _curl_with_range(self, url: str) -> bool:
        ua = random.choice(CONFIG.USER_AGENTS)
        ranges = ["0-102400", "102401-204800", "204801-307200"]
        ok = False
        for r in ranges:
            cmd = [
                "curl", "-s", "-o", "/dev/null",
                "-L", "--max-time", "15", "--compressed",
                "-H", f"User-Agent: {ua}",
                "-H", f"Range: bytes={r}",
                "--insecure", url,
            ]
            try:
                subprocess.run(cmd, timeout=20, capture_output=True)
                ok = True
            except Exception:
                pass
        return ok

    # ─── Assets pesados por dominio ─────────────────────────────────────────

    def _download_heavy_assets(self, end_time: float) -> int:
        if time.time() >= end_time:
            return 0

        heavy_urls: List[str] = []
        base = f"https://{self.domain}"

        for resource in CONFIG.HEAVY_RESOURCES:
            heavy_urls.append(f"{base}{resource}")

        # ── Dominios existentes ──────────────────────────────────────────────

        if "wikipedia" in self.domain:
            heavy_urls.extend([
                f"{base}/wiki/Python_(programming_language)",
                f"{base}/wiki/OSI_model",
                f"{base}/wiki/Denial-of-service_attack",
                f"{base}/wiki/Deep_learning",
                f"{base}/wiki/Computer_network",
                f"{base}/wiki/Internet_protocol_suite",
                f"{base}/wiki/Transmission_Control_Protocol",
                f"{base}/wiki/User_Datagram_Protocol",
                f"{base}/wiki/Intrusion_detection_system",
                f"{base}/wiki/Machine_learning",
                "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c3/Python-logo-notext.svg/800px-Python-logo-notext.svg.png",
            ])

        elif "debian" in self.domain and "packages" not in self.domain:
            heavy_urls.extend([
                f"{base}/distrib/packages.en.html",
                f"{base}/News/",
                f"{base}/doc/",
                f"{base}/security/",
                "https://packages.debian.org/stable/",
                "https://packages.debian.org/bookworm/allpackages",
                "https://security.debian.org/",
                "https://cdimage.debian.org/debian-cd/current/",
            ])

        elif "packages.debian" in self.domain:
            heavy_urls.extend([
                f"{base}/stable/",
                f"{base}/bookworm/allpackages",
                f"{base}/search?keywords=python&searchon=names&suite=stable",
                f"{base}/search?keywords=network&searchon=names&suite=stable",
                f"{base}/search?keywords=security&searchon=names&suite=stable",
            ])

        elif "kernel" in self.domain:
            heavy_urls.extend([
                "https://www.kernel.org/pub/",
                "https://cdn.kernel.org/pub/linux/kernel/",
                f"{base}/releases.json",
                f"{base}/category/releases.html",
            ])

        elif "docs.python" in self.domain:
            heavy_urls.extend([
                f"{base}/3/library/index.html",
                f"{base}/3/library/socket.html",
                f"{base}/3/library/subprocess.html",
                f"{base}/3/library/asyncio.html",
                f"{base}/3/library/pathlib.html",
                f"{base}/3/tutorial/index.html",
                f"{base}/3/reference/index.html",
                f"{base}/3/objects.inv",
            ])

        elif "python" in self.domain:
            heavy_urls.extend([
                f"{base}/ftp/python/",
                f"{base}/3/library/index.html",
                f"{base}/3/library/socket.html",
                f"{base}/3/library/subprocess.html",
                f"{base}/3/library/asyncio.html",
                "https://pypi.org/pypi/requests/json",
                "https://pypi.org/pypi/numpy/json",
                "https://pypi.org/pypi/pandas/json",
                "https://pypi.org/simple/",
                "https://docs.python.org/3/objects.inv",
            ])

        elif "reuters" in self.domain:
            heavy_urls.extend([
                f"{base}/world/", f"{base}/technology/",
                f"{base}/science/", f"{base}/business/",
                f"{base}/markets/", f"{base}/world/europe/",
                f"{base}/world/us/",
            ])

        elif "bbc" in self.domain:
            heavy_urls.extend([
                f"{base}/news", f"{base}/news/technology",
                f"{base}/news/science_and_environment",
                f"{base}/news/world", f"{base}/sport",
                f"{base}/weather",
            ])

        elif "theguardian" in self.domain:
            heavy_urls.extend([
                f"{base}/international", f"{base}/technology",
                f"{base}/science", f"{base}/world",
                f"{base}/business", f"{base}/environment",
                f"{base}/uk-news",
            ])

        elif "github" in self.domain:
            heavy_urls.extend([
                f"{base}/explore", f"{base}/trending",
                f"{base}/topics/python",
                f"{base}/topics/machine-learning",
                f"{base}/topics/networking",
                f"{base}/topics/security",
                f"{base}/topics/devops",
            ])

        elif "developer.mozilla" in self.domain or ("mozilla" in self.domain and "addons" not in self.domain):
            heavy_urls.extend([
                f"{base}/en-US/docs/Web/HTML",
                f"{base}/en-US/docs/Web/CSS",
                f"{base}/en-US/docs/Web/JavaScript",
                f"{base}/en-US/docs/Web/API",
                f"{base}/en-US/docs/Web/HTTP",
                f"{base}/en-US/docs/Learn",
                f"{base}/en-US/docs/Web/Security",
            ])

        elif "lobste" in self.domain:
            for page in range(1, 8):
                heavy_urls.append(f"{base}/?page={page}")
            heavy_urls.extend([
                f"{base}/t/programming", f"{base}/t/networking",
                f"{base}/t/security", f"{base}/t/python",
            ])

        elif "arstechnica" in self.domain:
            heavy_urls.extend([
                f"{base}/information-technology/", f"{base}/science/",
                f"{base}/tech-policy/", f"{base}/security/",
                f"{base}/gadgets/",
            ])

        elif "curl" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/", f"{base}/docs/manpage.html",
                f"{base}/docs/http3.html", f"{base}/download/",
                f"{base}/changes.html",
            ])

        elif "iana" in self.domain:
            heavy_urls.extend([
                f"{base}/domains/root/db", f"{base}/assignments/",
                f"{base}/protocols/", f"{base}/numbers",
                f"{base}/domains/",
            ])

        elif "ubuntu" in self.domain:
            heavy_urls.extend([
                f"{base}/download/", f"{base}/download/server",
                f"{base}/security/",
                "https://packages.ubuntu.com/",
                "https://changelogs.ubuntu.com/",
                "https://releases.ubuntu.com/",
            ])

        elif "nginx" in self.domain:
            heavy_urls.extend([
                f"{base}/resources/wiki/", f"{base}/en/docs/",
                f"{base}/en/download.html", f"{base}/en/changelog.html",
            ])

        elif "stackoverflow" in self.domain:
            heavy_urls.extend([
                f"{base}/questions", f"{base}/tags",
                f"{base}/questions/tagged/python",
                f"{base}/questions/tagged/networking",
                f"{base}/questions/tagged/machine-learning",
                f"{base}/questions/tagged/linux",
            ])

        elif "theguardian" in self.domain:
            heavy_urls.extend([
                f"{base}/international", f"{base}/technology",
                f"{base}/science", f"{base}/world",
                f"{base}/business", f"{base}/environment",
                f"{base}/uk-news",
            ])

        elif "apnews" in self.domain:
            heavy_urls.extend([
                f"{base}/hub/technology", f"{base}/hub/science",
                f"{base}/hub/world-news", f"{base}/hub/politics",
                f"{base}/hub/health",
            ])

        elif "npr" in self.domain:
            heavy_urls.extend([
                f"{base}/sections/news/", f"{base}/sections/technology/",
                f"{base}/sections/science/", f"{base}/sections/health-shots/",
                f"{base}/programs/all-things-considered/",
            ])

        elif "addons.mozilla" in self.domain:
            heavy_urls.extend([
                f"{base}/es-ES/firefox/",
                f"{base}/es-ES/firefox/extensions/",
                f"{base}/es-ES/firefox/themes/",
                f"{base}/es-ES/firefox/search/?q=privacy",
                f"{base}/es-ES/firefox/search/?q=vpn",
                f"{base}/es-ES/firefox/search/?q=adblocker",
            ])

        elif "dev.to" in self.domain:
            heavy_urls.extend([
                f"{base}/t/python", f"{base}/t/networking",
                f"{base}/t/security", f"{base}/t/linux",
                f"{base}/t/opensource", f"{base}/top/week",
                f"{base}/top/month",
            ])

        elif "cloudflare" in self.domain:
            heavy_urls.extend([
                f"{base}/learning/",
                f"{base}/learning/ddos/what-is-a-ddos-attack/",
                f"{base}/learning/network-layer/what-is-a-packet/",
                f"{base}/learning/dns/what-is-dns/",
                f"{base}/learning/ssl/what-is-ssl/",
                f"{base}/products/",
            ])

        elif "gutenberg" in self.domain:
            heavy_urls.extend([
                f"{base}/ebooks/search/?query=python",
                f"{base}/ebooks/search/?query=computer+science",
                f"{base}/ebooks/1342", f"{base}/ebooks/84",
                f"{base}/ebooks/2701", f"{base}/ebooks/11",
                f"{base}/cache/epub/1342/pg1342.txt",
            ])

        elif "pypi" in self.domain:
            heavy_urls.extend([
                f"{base}/pypi/requests/json", f"{base}/pypi/numpy/json",
                f"{base}/pypi/pandas/json", f"{base}/pypi/scikit-learn/json",
                f"{base}/pypi/flask/json", f"{base}/pypi/django/json",
                f"{base}/pypi/tensorflow/json",
                f"{base}/simple/", f"{base}/stats/",
            ])

        elif "arxiv" in self.domain:
            heavy_urls.extend([
                f"{base}/abs/2106.09685", f"{base}/abs/1706.03762",
                f"{base}/abs/2301.07543",
                f"{base}/list/cs.NI/recent", f"{base}/list/cs.CR/recent",
                f"{base}/list/cs.LG/recent",
                f"{base}/search/?query=ddos&searchtype=all",
                f"{base}/pdf/1706.03762",
            ])

        elif "nasa" in self.domain:
            heavy_urls.extend([
                f"{base}/missions/", f"{base}/solar-system/",
                f"{base}/images/", f"{base}/news/",
                f"{base}/centers/", f"{base}/multimedia/imagegallery/",
                "https://apod.nasa.gov/apod/astropix.html",
                "https://api.nasa.gov/",
            ])

        elif "microsoft" in self.domain:
            heavy_urls.extend([
                f"{base}/en-us/", f"{base}/en-us/microsoft-365/",
                f"{base}/en-us/windows/",
                "https://docs.microsoft.com/en-us/",
                "https://learn.microsoft.com/en-us/",
                "https://azure.microsoft.com/en-us/",
            ])

        # ── 15 dominios nuevos ───────────────────────────────────────────────

        elif "w3schools" in self.domain:
            heavy_urls.extend([
                f"{base}/python/",
                f"{base}/python/python_intro.asp",
                f"{base}/html/",
                f"{base}/css/",
                f"{base}/js/",
                f"{base}/sql/",
                f"{base}/linux/",
                f"{base}/cybersecurity/",
                f"{base}/dsa/",
                f"{base}/howto/",
                f"{base}/statistics/",
            ])

        elif "geeksforgeeks" in self.domain:
            heavy_urls.extend([
                f"{base}/python-programming-language/",
                f"{base}/computer-network-tutorials/",
                f"{base}/machine-learning/",
                f"{base}/data-structures/",
                f"{base}/linux-commands/",
                f"{base}/operating-systems/",
                f"{base}/dbms/",
                f"{base}/software-engineering/",
                f"{base}/web-technology/",
                f"{base}/cybersecurity-tutorial/",
                f"{base}/devops-tutorial/",
            ])

        elif "httpd.apache" in self.domain or ("apache" in self.domain and "httpd" in self.domain):
            heavy_urls.extend([
                f"{base}/docs/2.4/",
                f"{base}/docs/2.4/mod/",
                f"{base}/docs/2.4/mod/core.html",
                f"{base}/docs/2.4/mod/mod_proxy.html",
                f"{base}/docs/2.4/mod/mod_ssl.html",
                f"{base}/docs/2.4/configuring.html",
                f"{base}/docs/2.4/vhosts/",
                f"{base}/docs/2.4/howto/",
                f"{base}/docs/2.4/logs.html",
                f"{base}/docs/2.4/urlmapping.html",
            ])

        elif "postgresql" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/current/",
                f"{base}/docs/current/sql-commands.html",
                f"{base}/docs/current/datatype.html",
                f"{base}/docs/current/functions.html",
                f"{base}/docs/current/indexes.html",
                f"{base}/docs/current/performance-tips.html",
                f"{base}/docs/current/backup.html",
                f"{base}/docs/current/high-availability.html",
                f"{base}/download/",
            ])

        elif "mysql" in self.domain:
            heavy_urls.extend([
                f"{base}/doc/refman/8.0/en/",
                f"{base}/doc/refman/8.0/en/sql-statements.html",
                f"{base}/doc/refman/8.0/en/data-types.html",
                f"{base}/doc/refman/8.0/en/functions.html",
                f"{base}/doc/refman/8.0/en/optimization.html",
                f"{base}/doc/refman/8.0/en/backup-and-recovery.html",
                f"{base}/doc/refman/8.0/en/replication.html",
                f"{base}/downloads/",
            ])

        elif "redis" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/",
                f"{base}/docs/manual/",
                f"{base}/docs/manual/data-types/",
                f"{base}/docs/manual/data-structures/",
                f"{base}/docs/commands/",
                f"{base}/docs/manual/replication/",
                f"{base}/docs/manual/persistence/",
                f"{base}/docs/manual/clustering/",
                f"{base}/docs/manual/security/",
                f"{base}/download/",
            ])

        elif "elastic" in self.domain:
            heavy_urls.extend([
                f"{base}/guide/en/elasticsearch/reference/current/",
                f"{base}/guide/en/elasticsearch/reference/current/rest-apis.html",
                f"{base}/guide/en/kibana/current/",
                f"{base}/guide/en/logstash/current/",
                f"{base}/guide/en/beats/filebeat/current/",
                f"{base}/guide/en/elasticsearch/reference/current/query-dsl.html",
                f"{base}/guide/en/elasticsearch/reference/current/mapping.html",
                f"{base}/downloads/",
                f"{base}/what-is/elasticsearch/",
            ])

        elif "grafana" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/grafana/latest/",
                f"{base}/docs/grafana/latest/dashboards/",
                f"{base}/docs/grafana/latest/panels-visualizations/",
                f"{base}/docs/grafana/latest/alerting/",
                f"{base}/docs/grafana/latest/datasources/",
                f"{base}/docs/grafana/latest/administration/",
                f"{base}/grafana/download/",
                f"{base}/blog/",
                f"{base}/solutions/",
            ])

        elif "prometheus" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/introduction/overview/",
                f"{base}/docs/prometheus/latest/querying/basics/",
                f"{base}/docs/prometheus/latest/querying/functions/",
                f"{base}/docs/prometheus/latest/configuration/configuration/",
                f"{base}/docs/prometheus/latest/storage/",
                f"{base}/docs/prometheus/latest/federation/",
                f"{base}/docs/alerting/latest/alertmanager/",
                f"{base}/download/",
                f"{base}/community/",
            ])

        elif "ansible" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/",
                "https://docs.ansible.com/ansible/latest/",
                "https://docs.ansible.com/ansible/latest/playbook_guide/",
                "https://docs.ansible.com/ansible/latest/collections/",
                "https://docs.ansible.com/ansible/latest/inventory_guide/",
                "https://docs.ansible.com/ansible/latest/module_plugin_guide/",
                "https://docs.ansible.com/ansible/latest/reference_appendices/",
                f"{base}/use-cases/",
                f"{base}/community/",
            ])

        elif "kubernetes" in self.domain:
            heavy_urls.extend([
                f"{base}/docs/",
                f"{base}/docs/concepts/",
                f"{base}/docs/concepts/workloads/",
                f"{base}/docs/concepts/networking/",
                f"{base}/docs/concepts/storage/",
                f"{base}/docs/concepts/security/",
                f"{base}/docs/tasks/",
                f"{base}/docs/reference/",
                f"{base}/docs/tutorials/",
                f"{base}/docs/setup/",
                f"{base}/blog/",
            ])

        elif "docker" in self.domain:
            heavy_urls.extend([
                f"{base}/",
                f"{base}/get-started/",
                f"{base}/get-started/overview/",
                f"{base}/engine/",
                f"{base}/engine/reference/commandline/",
                f"{base}/compose/",
                f"{base}/compose/compose-file/",
                f"{base}/network/",
                f"{base}/storage/",
                f"{base}/security/",
                f"{base}/desktop/",
            ])

        elif "rust-lang" in self.domain:
            heavy_urls.extend([
                f"{base}/learn/",
                f"{base}/learn/get-started",
                "https://doc.rust-lang.org/book/",
                "https://doc.rust-lang.org/book/ch01-00-getting-started.html",
                "https://doc.rust-lang.org/std/",
                "https://doc.rust-lang.org/cargo/",
                "https://doc.rust-lang.org/rustdoc/",
                "https://doc.rust-lang.org/reference/",
                "https://crates.io/",
                "https://crates.io/crates?sort=downloads",
            ])

        elif "go.dev" in self.domain:
            heavy_urls.extend([
                f"{base}/doc/",
                f"{base}/doc/tutorial/",
                f"{base}/doc/effective_go",
                f"{base}/ref/spec",
                f"{base}/pkg/",
                f"{base}/pkg/net/",
                f"{base}/pkg/net/http/",
                f"{base}/pkg/os/",
                f"{base}/blog/",
                f"{base}/solutions/",
                "https://pkg.go.dev/std",
            ])

        elif "nodejs" in self.domain:
            heavy_urls.extend([
                f"{base}/en/docs/",
                f"{base}/en/docs/guides/",
                f"{base}/en/docs/guides/getting-started-guide/",
                f"{base}/api/",
                f"{base}/api/http.html",
                f"{base}/api/net.html",
                f"{base}/api/fs.html",
                f"{base}/api/stream.html",
                f"{base}/api/crypto.html",
                f"{base}/en/download/",
                f"{base}/en/blog/",
            ])

        # Descargar en paralelo
        count = 0
        with ThreadPoolExecutor(max_workers=CONFIG.MAX_PARALLEL_WORKERS) as executor:
            futures = {
                executor.submit(self._curl_request, url): url
                for url in heavy_urls
                if time.time() < end_time
            }
            for future in as_completed(futures):
                try:
                    if future.result():
                        count += 1
                except Exception:
                    pass

        return count

    # ─── Requests paralelos ──────────────────────────────────────────────────

    def _parallel_requests(self, urls: List[str], end_time: float) -> int:
        success_count = 0
        if time.time() >= end_time:
            return 0

        def _do_request(url: str) -> bool:
            roll = random.random()
            if roll < 0.5:
                return self._wget_simple(url)
            elif roll < 0.8:
                return self._curl_request(url)
            else:
                return self._curl_with_range(url)

        with ThreadPoolExecutor(max_workers=CONFIG.MAX_PARALLEL_WORKERS) as executor:
            futures = {
                executor.submit(_do_request, url): url
                for url in urls
                if time.time() < end_time
            }
            for future in as_completed(futures):
                try:
                    if future.result():
                        success_count += 1
                except Exception:
                    pass

        return success_count

    # ─── Generación de variantes de URL ─────────────────────────────────────

    def _url_variants(self) -> List[str]:
        base = f"https://{self.domain}"
        variants = [self.url, base]

        for resource in CONFIG.HEAVY_RESOURCES:
            variants.append(f"{base}{resource}")

        # ── Dominios existentes ──────────────────────────────────────────────

        if "github" in self.domain:
            variants += [
                f"{base}/explore", f"{base}/trending",
                f"{base}/topics/python", f"{base}/topics/machine-learning",
                f"{base}/topics/networking", f"{base}/topics/security",
                f"{base}/topics/linux",
            ]
        elif "wikipedia" in self.domain:
            variants += [
                f"{base}/wiki/Main_Page",
                f"{base}/wiki/Python_(programming_language)",
                f"{base}/wiki/Computer_network",
                f"{base}/wiki/Deep_learning",
                f"{base}/wiki/Intrusion_detection_system",
                f"{base}/wiki/Network_packet",
                f"{base}/wiki/Transmission_Control_Protocol",
                f"{base}/wiki/Denial-of-service_attack",
                f"{base}/wiki/Machine_learning",
                f"{base}/wiki/OSI_model",
            ]
        elif "stackoverflow" in self.domain:
            variants += [
                f"{base}/questions", f"{base}/tags",
                f"{base}/questions/tagged/python",
                f"{base}/questions/tagged/networking",
                f"{base}/questions/tagged/machine-learning",
                f"{base}/questions/tagged/linux",
            ]
        elif any(x in self.domain for x in ["bbc", "guardian", "reuters"]):
            variants += [
                f"{base}/news", f"{base}/technology",
                f"{base}/science", f"{base}/world",
                f"{base}/business", f"{base}/markets",
            ]
        elif "apnews" in self.domain:
            variants += [
                f"{base}/hub/technology", f"{base}/hub/science",
                f"{base}/hub/world-news", f"{base}/hub/politics",
            ]
        elif "npr" in self.domain:
            variants += [
                f"{base}/sections/news/",
                f"{base}/sections/technology/",
                f"{base}/sections/science/",
            ]
        elif "addons.mozilla" in self.domain:
            variants += [
                f"{base}/es-ES/firefox/extensions/",
                f"{base}/es-ES/firefox/themes/",
                f"{base}/es-ES/firefox/search/?q=privacy",
                f"{base}/es-ES/firefox/search/?q=vpn",
            ]
        elif "mozilla" in self.domain:
            variants += [
                f"{base}/en-US/docs/Web/HTML",
                f"{base}/en-US/docs/Web/CSS",
                f"{base}/en-US/docs/Web/JavaScript",
                f"{base}/en-US/docs/Web/API",
                f"{base}/en-US/docs/Web/HTTP",
                f"{base}/en-US/docs/Learn",
            ]
        elif "docs.python" in self.domain:
            variants += [
                f"{base}/3/library/index.html",
                f"{base}/3/library/socket.html",
                f"{base}/3/library/asyncio.html",
                f"{base}/3/tutorial/index.html",
                f"{base}/3/reference/index.html",
            ]
        elif "python" in self.domain:
            variants += [
                f"{base}/3/library/index.html",
                f"{base}/3/tutorial/index.html",
                f"{base}/3/library/socket.html",
                f"{base}/3/library/subprocess.html",
                f"{base}/3/library/asyncio.html",
            ]
        elif "nginx" in self.domain:
            variants += [
                f"{base}/resources/wiki/",
                f"{base}/en/docs/",
                f"{base}/en/download.html",
            ]
        elif "packages.debian" in self.domain:
            variants += [
                f"{base}/stable/",
                f"{base}/bookworm/allpackages",
                f"{base}/search?keywords=python&searchon=names&suite=stable",
                f"{base}/search?keywords=network&searchon=names&suite=stable",
            ]
        elif "debian" in self.domain:
            variants += [
                f"{base}/distrib/packages.en.html",
                f"{base}/News/", f"{base}/doc/", f"{base}/security/",
            ]
        elif "kernel" in self.domain:
            variants += [
                f"{base}/pub/", f"{base}/releases.json",
                f"{base}/category/releases.html",
            ]
        elif "ubuntu" in self.domain:
            variants += [
                f"{base}/download/", f"{base}/security/", f"{base}/blog/",
            ]
        elif "curl" in self.domain:
            variants += [
                f"{base}/docs/", f"{base}/docs/manpage.html",
                f"{base}/download/",
            ]
        elif "iana" in self.domain:
            variants += [
                f"{base}/domains/root/db",
                f"{base}/protocols/", f"{base}/numbers",
            ]
        elif "lobste" in self.domain:
            for page in range(1, 5):
                variants.append(f"{base}/?page={page}")
            variants += [f"{base}/t/programming", f"{base}/t/networking"]
        elif "arstechnica" in self.domain:
            variants += [
                f"{base}/information-technology/",
                f"{base}/science/", f"{base}/security/",
            ]
        elif "dev.to" in self.domain:
            variants += [
                f"{base}/t/python", f"{base}/t/networking",
                f"{base}/t/security", f"{base}/t/linux",
                f"{base}/top/week",
            ]
        elif "cloudflare" in self.domain:
            variants += [
                f"{base}/learning/",
                f"{base}/learning/ddos/what-is-a-ddos-attack/",
                f"{base}/learning/dns/what-is-dns/",
                f"{base}/products/",
            ]
        elif "gutenberg" in self.domain:
            variants += [
                f"{base}/ebooks/search/?query=python",
                f"{base}/ebooks/1342", f"{base}/ebooks/2701",
                f"{base}/cache/epub/1342/pg1342.txt",
            ]
        elif "pypi" in self.domain:
            variants += [
                f"{base}/pypi/requests/json",
                f"{base}/pypi/numpy/json",
                f"{base}/pypi/pandas/json",
                f"{base}/simple/",
            ]
        elif "arxiv" in self.domain:
            variants += [
                f"{base}/abs/2106.09685", f"{base}/abs/1706.03762",
                f"{base}/list/cs.NI/recent", f"{base}/list/cs.CR/recent",
                f"{base}/search/?query=ddos&searchtype=all",
            ]
        elif "nasa" in self.domain:
            variants += [
                f"{base}/missions/", f"{base}/solar-system/",
                f"{base}/images/", f"{base}/news/",
                "https://apod.nasa.gov/apod/astropix.html",
            ]
        elif "microsoft" in self.domain:
            variants += [
                "https://docs.microsoft.com/en-us/",
                "https://learn.microsoft.com/en-us/",
                "https://azure.microsoft.com/en-us/",
            ]

        # ── 15 dominios nuevos ───────────────────────────────────────────────

        elif "w3schools" in self.domain:
            variants += [
                f"{base}/python/", f"{base}/html/",
                f"{base}/css/", f"{base}/js/",
                f"{base}/sql/", f"{base}/linux/",
                f"{base}/cybersecurity/", f"{base}/dsa/",
            ]
        elif "geeksforgeeks" in self.domain:
            variants += [
                f"{base}/python-programming-language/",
                f"{base}/computer-network-tutorials/",
                f"{base}/machine-learning/",
                f"{base}/data-structures/",
                f"{base}/linux-commands/",
                f"{base}/cybersecurity-tutorial/",
                f"{base}/devops-tutorial/",
            ]
        elif "httpd.apache" in self.domain or ("apache" in self.domain and "httpd" in self.domain):
            variants += [
                f"{base}/docs/2.4/",
                f"{base}/docs/2.4/mod/",
                f"{base}/docs/2.4/mod/core.html",
                f"{base}/docs/2.4/mod/mod_proxy.html",
                f"{base}/docs/2.4/vhosts/",
                f"{base}/docs/2.4/howto/",
            ]
        elif "postgresql" in self.domain:
            variants += [
                f"{base}/docs/current/",
                f"{base}/docs/current/sql-commands.html",
                f"{base}/docs/current/datatype.html",
                f"{base}/docs/current/functions.html",
                f"{base}/docs/current/indexes.html",
                f"{base}/download/",
            ]
        elif "mysql" in self.domain:
            variants += [
                f"{base}/doc/refman/8.0/en/",
                f"{base}/doc/refman/8.0/en/sql-statements.html",
                f"{base}/doc/refman/8.0/en/data-types.html",
                f"{base}/doc/refman/8.0/en/functions.html",
                f"{base}/doc/refman/8.0/en/optimization.html",
                f"{base}/downloads/",
            ]
        elif "redis" in self.domain:
            variants += [
                f"{base}/docs/", f"{base}/docs/manual/",
                f"{base}/docs/manual/data-types/",
                f"{base}/docs/commands/",
                f"{base}/docs/manual/replication/",
                f"{base}/docs/manual/clustering/",
                f"{base}/download/",
            ]
        elif "elastic" in self.domain:
            variants += [
                f"{base}/guide/en/elasticsearch/reference/current/",
                f"{base}/guide/en/kibana/current/",
                f"{base}/guide/en/logstash/current/",
                f"{base}/guide/en/elasticsearch/reference/current/query-dsl.html",
                f"{base}/downloads/",
                f"{base}/what-is/elasticsearch/",
            ]
        elif "grafana" in self.domain:
            variants += [
                f"{base}/docs/grafana/latest/",
                f"{base}/docs/grafana/latest/dashboards/",
                f"{base}/docs/grafana/latest/alerting/",
                f"{base}/docs/grafana/latest/datasources/",
                f"{base}/grafana/download/",
                f"{base}/blog/",
            ]
        elif "prometheus" in self.domain:
            variants += [
                f"{base}/docs/introduction/overview/",
                f"{base}/docs/prometheus/latest/querying/basics/",
                f"{base}/docs/prometheus/latest/querying/functions/",
                f"{base}/docs/prometheus/latest/configuration/configuration/",
                f"{base}/download/",
            ]
        elif "ansible" in self.domain:
            variants += [
                "https://docs.ansible.com/ansible/latest/",
                "https://docs.ansible.com/ansible/latest/playbook_guide/",
                "https://docs.ansible.com/ansible/latest/collections/",
                "https://docs.ansible.com/ansible/latest/inventory_guide/",
                f"{base}/use-cases/",
            ]
        elif "kubernetes" in self.domain:
            variants += [
                f"{base}/docs/concepts/",
                f"{base}/docs/concepts/workloads/",
                f"{base}/docs/concepts/networking/",
                f"{base}/docs/concepts/security/",
                f"{base}/docs/tasks/",
                f"{base}/docs/tutorials/",
                f"{base}/blog/",
            ]
        elif "docker" in self.domain:
            variants += [
                f"{base}/get-started/",
                f"{base}/engine/",
                f"{base}/engine/reference/commandline/",
                f"{base}/compose/",
                f"{base}/compose/compose-file/",
                f"{base}/network/",
                f"{base}/security/",
            ]
        elif "rust-lang" in self.domain:
            variants += [
                f"{base}/learn/", f"{base}/learn/get-started",
                "https://doc.rust-lang.org/book/",
                "https://doc.rust-lang.org/std/",
                "https://doc.rust-lang.org/cargo/",
                "https://crates.io/",
                "https://crates.io/crates?sort=downloads",
            ]
        elif "go.dev" in self.domain:
            variants += [
                f"{base}/doc/", f"{base}/doc/tutorial/",
                f"{base}/doc/effective_go", f"{base}/ref/spec",
                f"{base}/pkg/", f"{base}/pkg/net/http/",
                f"{base}/blog/",
                "https://pkg.go.dev/std",
            ]
        elif "nodejs" in self.domain:
            variants += [
                f"{base}/en/docs/",
                f"{base}/en/docs/guides/",
                f"{base}/api/", f"{base}/api/http.html",
                f"{base}/api/net.html", f"{base}/api/stream.html",
                f"{base}/en/download/", f"{base}/en/blog/",
            ]

        # Subdominios genéricos
        for prefix in ["www", "cdn", "static", "api", "docs"]:
            variants.append(f"https://{prefix}.{self.domain}")

        return list(set(variants))

    # ─── Sesión principal ────────────────────────────────────────────────────

    def generate_session(self, duration_seconds: float) -> Dict[str, Any]:
        end_time = time.time() + duration_seconds
        requests_http = 0
        queries_dns = 0
        traffic_generated = False

        variants = self._url_variants()

        # FASE 1: wget recursivo agresivo
        print(f"  [+] Fase 1: wget recursivo level=3 para {self.domain}")
        if time.time() < end_time - 30:
            with ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(self._wget_recursive, 3)
                f2 = executor.submit(self._wget_recursive, 2)
                for f in [f1, f2]:
                    try:
                        if f.result():
                            requests_http += 1
                            traffic_generated = True
                    except Exception:
                        pass

        # FASE 1b: assets pesados específicos
        print(f"  [+] Fase 1b: assets pesados para {self.domain}")
        count = self._download_heavy_assets(end_time)
        requests_http += count
        if count > 0:
            traffic_generated = True

        # DNS burst inicial
        queries_dns += self._generate_dns_burst(
            random.randint(CONFIG.DNS_QUERIES_MIN * 2, CONFIG.DNS_QUERIES_MAX * 2)
        )

        # FASE 2: loop de alta densidad
        print(f"  [+] Fase 2: loop paralelo de alta densidad para {self.domain}")
        iteration = 0

        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining < 2:
                break

            iteration += 1

            if iteration % 5 == 0 and remaining > 45:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    f1 = executor.submit(self._wget_recursive, 2)
                    f2 = executor.submit(self._wget_recursive, 3)
                    for f in [f1, f2]:
                        try:
                            if f.result():
                                requests_http += 1
                                traffic_generated = True
                        except Exception:
                            pass

            if iteration % 10 == 0 and remaining > 60:
                count = self._download_heavy_assets(end_time)
                requests_http += count

            batch_size = min(CONFIG.PARALLEL_BATCH_SIZE, len(variants))
            batch_urls = random.sample(variants, batch_size)
            count = self._parallel_requests(batch_urls, end_time)
            requests_http += count
            if count > 0:
                traffic_generated = True

            if iteration % 2 == 0:
                queries_dns += self._generate_dns_burst(
                    random.randint(CONFIG.DNS_QUERIES_MIN, CONFIG.DNS_QUERIES_MAX)
                )

            pause = random.uniform(0.02, 0.15)
            if time.time() + pause < end_time:
                time.sleep(pause)

        print(f"  [✓] {self.domain}: {requests_http} HTTP requests, {queries_dns} DNS queries")

        return {
            "requests_http": requests_http,
            "queries_dns": queries_dns,
            "traffic_generated": traffic_generated,
        }
