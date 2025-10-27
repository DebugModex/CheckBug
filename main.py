#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Atlas (refactored) - Simple web scanning utilities
Keep the same functionality as original script but with:
 - safer network calls (timeouts / exception handling)
 - thread-based concurrency for blocking calls
 - safer JSON/file loading
 - clearer structure and fewer global mutable states
"""
from __future__ import annotations

import sys
import os
import json
import socket

import datetime
import concurrent.futures
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen
from typing import List, Dict, Tuple, Optional

import requests
from colorama import init as colorama_init, Fore

# Initialize colorama
colorama_init(autoreset=True)

VERSION = "1.0.2-A"


BANNER = f"""{Fore.BLUE}
 ██████ ██   ██ ███████  ██████ ██   ██     ██████  ██    ██  ██████  
██      ██   ██ ██      ██      ██  ██      ██   ██ ██    ██ ██       
██      ███████ █████   ██      █████       ██████  ██    ██ ██   ███ 
██      ██   ██ ██      ██      ██  ██      ██   ██ ██    ██ ██    ██ 
 ██████ ██   ██ ███████  ██████ ██   ██     ██████   ██████   ██████  
                                                                      
                                                                      {Fore.WHITE} 

CHECK BUG  —  owned by Debug Mode
Youtube: DebugModex
{Fore.WHITE}"""



DEFAULT_DEV_PORTS = sorted(list({
    8080, 8081, 4434,
    5000, 3000, 3001,
    4000, 4443, 5001,
    8443
}))  # deduped and sorted

DEFAULT_SENSITIVE_FILES = [
    "/.env", "/.git/config", "/backup.zip",
    "/phpinfo.php", "/admin.php", "/robots.txt"
]

REQUESTS_TIMEOUT = 5  # seconds for network requests
PORT_TIMEOUT = 2      # seconds for socket connections
MAX_WORKERS = 10      # for thread pool


def ctime() -> str:
    return datetime.datetime.now().strftime('%H:%M:%S')


def line(length: int, ch: str = '-') -> str:
    return ch * length


def safe_load_json(path: str) -> Optional[object]:
    """Load JSON from file safely, return None on failure."""
    if not os.path.exists(path):
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.YELLOW}WARN{Fore.WHITE}] {path} not found.")
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.RED}ERROR{Fore.WHITE}] Invalid JSON in {path}: {e}")
        return None
    except Exception as e:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.RED}ERROR{Fore.WHITE}] Failed to read {path}: {e}")
        return None


class Atlas:
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        self.target_url = self._normalize_url(target_url)
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'AtlasScanner/1.0 (+https://example.com)'
        })
        self.dev_ports = DEFAULT_DEV_PORTS.copy()
        self.sensitive_files = DEFAULT_SENSITIVE_FILES.copy()

    @staticmethod
    def _normalize_url(url: str) -> str:
        u = url.strip()
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        return u

    def load_miss_configured(self, path: str = 'busting.txt') -> List[Dict]:
        data = safe_load_json(path)
        if not isinstance(data, list):
            return []
        return data

    def base_url(self) -> str:
        parsed = urlparse(self.target_url)
        scheme = parsed.scheme if parsed.scheme else 'http'
        return f"{scheme}://{parsed.netloc}"

    def get_domain(self) -> str:
        return urlparse(self.target_url).netloc

    def host2ip(self, host: Optional[str] = None) -> Optional[str]:
        try:
            host_to_resolve = host or self.get_domain()
            return socket.gethostbyname(host_to_resolve)
        except socket.gaierror:
            return None
        except Exception:
            return None

    def get_server_header(self) -> str:
        try:
            resp = self.session.head(self.target_url, allow_redirects=True, timeout=REQUESTS_TIMEOUT)
            return resp.headers.get("Server", "unknown")
        except requests.RequestException:
            return "unknown"

    def port_open(self, addr: str, port: int, timeout: int = PORT_TIMEOUT) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((addr, port))
                return result == 0
        except Exception:
            return False

    def dev_links(self) -> List[str]:
        host = self.get_domain()
        addr = self.host2ip(host)
        if not addr:
            return []
        results = []

        def check_port(p):
            if self.port_open(addr, p):
                return f"{self.base_url()}:{p}/"
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(self.dev_ports), MAX_WORKERS)) as ex:
            futures = {ex.submit(check_port, p): p for p in self.dev_ports}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)
        return sorted(results)

    def is_gruzifix(self) -> bool:
        """Check existence of /gruzifix.atlas — returns True if reachable (200)."""
        try:
            url = urljoin(self.target_url, "/gruzifix.atlas")
            r = self.session.get(url, allow_redirects=False, timeout=REQUESTS_TIMEOUT)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def extract_forms(self) -> List:
        """Return list of form tags from the main page (keeps original behavior)."""
        try:
            r = self.session.get(self.target_url, timeout=REQUESTS_TIMEOUT)
            from bs4 import BeautifulSoup  # local import in case not used elsewhere
            soup = BeautifulSoup(r.content, 'html.parser')
            return soup.find_all("form")
        except Exception:
            return []

    def check_sensitive_files(self, additional: Optional[List[str]] = None) -> List[Dict]:
        """Check list of sensitive files, return found items with status."""
        files = (additional or []) + self.sensitive_files
        found = []

        def check(path):
            try:
                url = urljoin(self.base_url(), path)
                r = self.session.get(url, allow_redirects=False, timeout=REQUESTS_TIMEOUT)
                if r.status_code == 200:
                    return {"type": "Sensitive File Exposure", "file": path, "status": r.status_code}
            except requests.RequestException:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(files), MAX_WORKERS)) as ex:
            futures = {ex.submit(check, p): p for p in files}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    found.append(res)
        return found

    def check_headers_security(self) -> List[Dict]:
        """Return list of missing security headers found on the main URL."""
        try:
            r = self.session.get(self.target_url, timeout=REQUESTS_TIMEOUT)
            headers = {k.lower(): v for k, v in r.headers.items()}
        except requests.RequestException:
            headers = {}

        security_headers = {
            "x-frame-options": "Missing - Clickjacking protection",
            "x-content-type-options": "Missing - MIME sniffing protection",
            "strict-transport-security": "Missing - HTTPS enforcement",
            "content-security-policy": "Missing - XSS protection"
        }

        found = []
        for header, msg in security_headers.items():
            if header not in headers:
                found.append({"type": "Security Header Missing", "header": header, "message": msg})
        return found

    def get_robots(self) -> Dict[str, List[str]]:
        """Parse robots.txt for Allow / Disallow lines for User-agent: *"""
        allows = []
        disallows = []
        try:
            url = urljoin(self.base_url(), "robots.txt")
            r = self.session.get(url, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return {"allow": allows, "disallow": disallows}
            content = r.text.splitlines()
            current_agent = None
            for ln in content:
                ln_stripped = ln.strip()
                if not ln_stripped or ln_stripped.startswith('#'):
                    continue
                low = ln_stripped.lower()
                if low.startswith("user-agent"):
                    # format: User-agent: <agent>
                    parts = ln_stripped.split(":", 1)
                    if len(parts) == 2:
                        current_agent = parts[1].strip()
                    else:
                        current_agent = None
                elif current_agent == "*" or current_agent == "*":
                    if low.startswith("disallow:"):
                        item = ln_stripped.split(":", 1)[1].strip()
                        if item:
                            disallows.append(item)
                    elif low.startswith("allow:"):
                        item = ln_stripped.split(":", 1)[1].strip()
                        if item:
                            allows.append(item)
            return {"allow": allows, "disallow": disallows}
        except requests.RequestException:
            return {"allow": allows, "disallow": disallows}


def run_scan(target: str):
    atlas = Atlas(target)

    # Header/banner
    print(BANNER)

    # Basic checks / info
    domain = atlas.get_domain()
    server = atlas.get_server_header()
    ip = atlas.host2ip()
    if ip is None:
        ip = "unknown"

    # Prepare dynamic line width based on longest candidate path
    miss_config = atlas.load_miss_configured() or []
    longest_path_len = 0
    for entry in miss_config:
        paths = entry.get("paths", []) + entry.get("rootPaths", [])
        for p in paths:
            if len(p) > longest_path_len:
                longest_path_len = len(p)
    liner_len = max(60, longest_path_len + 25)
    liner = line(liner_len)

    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Getting info about ({Fore.BLUE}{target}{Fore.WHITE})")
    print(liner)
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  DOMAIN.: {domain}")
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  SERVER.: {server}")
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  ADDRESS: {ip}")
    print(liner)

    # Miss-configured files (concurrent checks)
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Checking for miss-configured files")
    print(liner)
    miss_results = []

    # Build flat list of all paths annotated with critLevel
    annotated_paths: List[Tuple[str, str]] = []
    for entry in miss_config:
        crit = str(entry.get("critLevel", "0"))
        paths = entry.get("paths", []) + entry.get("rootPaths", [])
        for p in paths:
            annotated_paths.append((p, crit))

    def check_path_tuple(item: Tuple[str, str]) -> Optional[str]:
        path, crit = item
        full_url = urljoin(atlas.base_url(), path)
        try:
            r = atlas.session.get(full_url, allow_redirects=False, timeout=REQUESTS_TIMEOUT)
            # If gruzifix exists and file returns 200, handle like original logic:
            if atlas.is_gruzifix() and r.status_code == 200:
                return None
            if r.status_code != 404:
                # Format similar to original output (path + spacing + crit + code)
                pad_len = max(0, liner_len - len(path) - 1 - len("[00:00:00] [INFO]  ") - (len(str(r.status_code)) + 2))
                return f"{path}{' ' * pad_len}{Fore.YELLOW}{crit} {Fore.GREEN if r.status_code == 200 else Fore.WHITE}{r.status_code}"
        except requests.RequestException:
            return None

    if annotated_paths:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(check_path_tuple, p): p for p in annotated_paths}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    miss_results.append(res)

    for item in miss_results:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  {item}")

    if not miss_results:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}] {Fore.RED} No miss-configuration found!{Fore.WHITE}")

    print(liner)

    # Dev ports
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Scanning for dev-ports")
    print(liner)
    dev_links = atlas.dev_links()
    for d in dev_links:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  {d}")
    if not dev_links:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}] {Fore.RED} No dev-ports found!{Fore.WHITE}")

    print(liner)

    # robots.txt
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Scanning (robots.txt)")
    print(liner)
    robots = atlas.get_robots()
    allows = robots.get('allow', [])
    disallows = robots.get('disallow', [])

    for allow in allows:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  {Fore.GREEN}ALLOW    {Fore.WHITE}{allow}")
    for disallow in disallows:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  {Fore.RED}DISALLOW {Fore.WHITE}{disallow}")

    if not allows and not disallows:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}] {Fore.RED} No interesting items found!{Fore.WHITE}")

    print(liner)

    # Security headers
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Checking security headers")
    print(liner)
    headers_issues = atlas.check_headers_security()
    if headers_issues:
        for h in headers_issues:
            print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}]  {h['header']}: {h['message']}")
    else:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.GREEN}INFO{Fore.WHITE}] No missing security headers detected.")

    print(liner)

    # End
    print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.BLUE}EVENT{Fore.WHITE}] Scan complete.")
    print(liner)


def main():
    if len(sys.argv) < 2:
        print(BANNER)
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.RED}ERROR{Fore.WHITE}] No url specified")
        print("Usage: python atlas.py <target-url>")
        sys.exit(1)

    target = sys.argv[1].strip()
    try:
        run_scan(target)
    except KeyboardInterrupt:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.RED}ERROR{Fore.WHITE}] KeyboardInterrupt")
    except Exception as e:
        print(f"[{Fore.CYAN}{ctime()}{Fore.WHITE}] [{Fore.RED}ERROR{Fore.WHITE}] Unexpected error: {e}")


if __name__ == "__main__":
    main()
