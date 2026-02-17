#!/usr/bin/env python3
"""
scanner.py    Secure SDN Network Scanner
Multithreaded port scan (stealth + common), OS fingerprint, banner grab.

Usage:
  python3 scanner.py <IP> [--mode MODE] [--ports PORTS] [--threads N] [--timeout T] [--output FILE]

Modes:
  common    TCP-connect scan of ~1000 well-known ports  (default)
  stealth   SYN half-open scan (requires root / CAP_NET_RAW)
  os        OS fingerprinting via TTL + TCP-window heuristics
  banner    Banner / service-version grabbing on open ports
  full      Runs common + os + banner together

Examples:
  python3 scanner.py ip
  python3 scanner.py {ip} --mode stealth --ports 1-1024
  python3 scanner.py {ip} --mode full --threads 200 --output report.txt
  python3 scanner.py {ip} --mode os
  python3 scanner.py {ip} --mode banner --ports 22,80,443,8080
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import random
import re
import select
import socket
import struct
import sys
import textwrap
import time
from datetime import datetime

NO_COLOR = not sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"

RED    = lambda t: _c("1;31", t)
GREEN  = lambda t: _c("1;32", t)
YELLOW = lambda t: _c("1;33", t)
CYAN   = lambda t: _c("1;36", t)
BLUE   = lambda t: _c("1;34", t)
GRAY   = lambda t: _c("90",   t)
BOLD   = lambda t: _c("1",    t)
DIM    = lambda t: _c("2",    t)

# Service / port name database (top ~1000 ports)
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 79, 80, 88, 110, 111, 119,
    123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445,
    465, 500, 512, 513, 514, 515, 587, 631, 636, 993, 995, 1080, 1194,
    1433, 1434, 1521, 1723, 1900, 2049, 2083, 2087, 2095, 2096, 2181,
    2375, 2376, 3000, 3306, 3389, 3690, 4444, 4848, 5000, 5432, 5900,
    5984, 6379, 6443, 6667, 7001, 7077, 7474, 8000, 8080, 8081, 8083,
    8086, 8088, 8089, 8161, 8443, 8888, 9000, 9090, 9092, 9200, 9300,
    9418, 9999, 10000, 11211, 27017, 27018, 28017, 50000, 50070, 61616,
]

# Extended to ~1000 by adding 1-1024 sweep range
FULL_COMMON = sorted(set(COMMON_PORTS + list(range(1, 1025))))

SERVICE_NAMES = {
    20: "FTP-data",   21: "FTP",        22: "SSH",        23: "Telnet",
    25: "SMTP",       53: "DNS",        67: "DHCP",       68: "DHCP",
    69: "TFTP",       79: "Finger",     80: "HTTP",       88: "Kerberos",
    110: "POP3",      111: "RPC",       119: "NNTP",      123: "NTP",
    135: "MS-RPC",    137: "NetBIOS",   138: "NetBIOS",   139: "NetBIOS",
    143: "IMAP",      161: "SNMP",      162: "SNMP-trap", 179: "BGP",
    194: "IRC",       389: "LDAP",      443: "HTTPS",     445: "SMB",
    465: "SMTPS",     500: "IKE",       512: "rexec",     513: "rlogin",
    514: "syslog",    515: "LPD",       587: "SMTP-sub",  631: "IPP",
    636: "LDAPS",     993: "IMAPS",     995: "POP3S",     1080: "SOCKS",
    1194: "OpenVPN",  1433: "MSSQL",    1434: "MSSQL-UDP",1521: "Oracle",
    1723: "PPTP",     1900: "UPnP",     2049: "NFS",      2181: "ZooKeeper",
    2375: "Docker",   2376: "Docker-TLS",3000: "Dev-HTTP", 3306: "MySQL",
    3389: "RDP",      3690: "SVN",      4444: "Metasploit",4848: "GlassFish",
    5000: "Dev-HTTP", 5432: "PostgreSQL",5900: "VNC",     5984: "CouchDB",
    6379: "Redis",    6443: "K8s-API",  6667: "IRC",      7001: "WebLogic",
    8000: "HTTP-alt", 8080: "HTTP-proxy",8081: "HTTP-alt",8443: "HTTPS-alt",
    8888: "Jupyter",  9000: "SonarQube",9090: "Prometheus",9092: "Kafka",
    9200: "Elasticsearch",9300: "ES-transport",9418: "Git",
    10000: "Webmin",  11211: "Memcached",27017: "MongoDB",
    50000: "SAP",     50070: "Hadoop",  61616: "ActiveMQ",
}

# ──────────────────────────────────────────────
# Banner probes: sent immediately after connect
# to elicit a service greeting or version string
# ──────────────────────────────────────────────
BANNER_PROBES = {
    "HTTP": b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "SMTP": b"EHLO scanner\r\n",
    "FTP":  None,   # FTP server speaks first
    "SSH":  None,   # SSH server speaks first
    "GENERIC": b"\r\n",
}

PORT_PROBE_MAP = {
    80: "HTTP",  8080: "HTTP", 8000: "HTTP", 8443: "HTTP",
    443: "HTTP", 8081: "HTTP", 3000: "HTTP",
    25: "SMTP",  465: "SMTP",  587: "SMTP",
    21: "FTP",
    22: "SSH",
}

# OS FINGERPRINT HEURISTICS
# Based on TTL in ICMP echo-reply and TCP window sizes (passive / active)
OS_TTL_MAP = [
    (range(60, 65),   "Linux / Android (TTL ~64)"),
    (range(125, 130), "Windows (TTL ~128)"),
    (range(252, 256), "Cisco IOS / Solaris (TTL ~255)"),
    (range(126, 131), "Windows Server"),
    (range(30, 35),   "Network device / some BSD (TTL ~32)"),
]

OS_WINDOW_MAP = {
    65535: "Windows (classic)",
    8192:  "Windows Vista+",
    5840:  "Linux 2.4 / 2.6",
    29200: "Linux 3.x+",
    64240: "Linux 4.x / 5.x (common default)",
    65392: "Linux (some distros)",
    4128:  "Cisco IOS",
    32768: "FreeBSD / macOS",
    65228: "macOS / iOS",
}


#  HELPER: parse port spec  "22,80,1-1024"
def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


#  HELPER: validate target IP
def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(RED(f"[!] Cannot resolve target: {target}"))
            sys.exit(1)



def section(title: str):
    width = 50
    bar = "─" * width
    print(f"\n{CYAN(bar)}")
    print(BOLD(f"  {title}"))
    print(CYAN(bar))

def result_line(port: int, state: str, service: str, extra: str = ""):
    svc_str  = YELLOW(f"{service:<16}") if service else " " * 16
    if state == "open":
        state_str = GREEN("open  ")
    elif state == "closed":
        state_str = GRAY("closed")
    else:
        state_str = DIM("filter")

    extra_str = GRAY(f"  {extra}") if extra else ""
    print(f"  {BOLD(str(port)):<16} {state_str}  {svc_str}{extra_str}")


#  1.  TCP CONNECT SCAN  (no root needed)
def tcp_connect_scan(target: str, port: int, timeout: float) -> str:
    """Returns 'open', 'closed', or 'filtered'."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return "open" if result == 0 else "closed"
    except socket.timeout:
        return "filtered"
    except (ConnectionRefusedError, OSError):
        return "closed"


def run_common_scan(target: str, ports: list[int], threads: int,
                    timeout: float) -> dict[int, str]:
    section(f"TCP Connect Scan  →  {target}  ({len(ports)} ports, {threads} threads)")
    results: dict[int, str] = {}
    open_count = 0
    done = 0
    total = len(ports)

    def scan_one(p):
        return p, tcp_connect_scan(target, p, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_one, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, state = fut.result()
            results[port] = state
            done += 1
            if state == "open":
                open_count += 1
                svc = SERVICE_NAMES.get(port, "unknown")
                result_line(port, state, svc)
            # Live progress on same line
            pct = done * 100 // total
            print(f"  {GRAY(f'Progress: {done}/{total}  ({pct}%)')}", end="\r")

    print(" " * 60, end="\r")   # clear progress line
    print(f"\n  {GREEN(str(open_count))} open port(s) found out of {total} scanned.")
    return results


#  2.  SYN STEALTH SCAN  (requires root)
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_syn_packet(src_ip: str, dst_ip: str, dst_port: int,
                      src_port: int) -> bytes:
    # IP header
    ip_ihl_ver = (4 << 4) | 5
    ip_tos = 0
    ip_tot_len = 0   # kernel fills this
    ip_id = random.randint(1000, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr,
    )

    # TCP header  (SYN flag = 0x02)
    seq      = random.randint(0, 2**32 - 1)
    ack_seq  = 0
    doff     = 5
    flags    = 0x02       # SYN
    window   = socket.htons(5840)
    check    = 0
    urg_ptr  = 0
    offset_res = (doff << 4) | 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, check, urg_ptr,
    )

    # TCP pseudo-header for checksum
    pseudo = struct.pack("!4s4sBBH",
        ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
    check = _checksum(pseudo + tcp_header)

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, check, urg_ptr,
    )

    return ip_header + tcp_header


def syn_probe(src_ip: str, dst_ip: str, dst_port: int,
              timeout: float) -> str:
    """
    Send a raw SYN, listen for SYN-ACK (open) or RST (closed).
    Falls back to 'filtered' on timeout.
    Requires CAP_NET_RAW / root.
    """
    src_port = random.randint(1024, 65535)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)

        pkt = _build_syn_packet(src_ip, dst_ip, dst_port, src_port)
        raw.sendto(pkt, (dst_ip, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            ready = select.select([raw], [], [], max(0, deadline - time.time()))
            if not ready[0]:
                break
            try:
                data, _ = raw.recvfrom(1024)
            except socket.timeout:
                break

            # Parse IP header (20 bytes) then TCP
            ip_hdr_len = (data[0] & 0x0F) * 4
            if len(data) < ip_hdr_len + 14:
                continue

            tcp_data = data[ip_hdr_len:]
            r_src_port = struct.unpack("!H", tcp_data[0:2])[0]
            r_dst_port = struct.unpack("!H", tcp_data[2:4])[0]
            tcp_flags  = tcp_data[13]

            if r_src_port == dst_port and r_dst_port == src_port:
                if tcp_flags & 0x12:   # SYN-ACK
                    # Send RST to close half-open
                    rst_pkt = _build_syn_packet(src_ip, dst_ip, dst_port,
                                                src_port)
                    try:
                        raw.sendto(rst_pkt, (dst_ip, 0))
                    except Exception:
                        pass
                    return "open"
                elif tcp_flags & 0x04:  # RST
                    return "closed"

        return "filtered"
    except PermissionError:
        print(RED("\n[!] Stealth scan requires root / CAP_NET_RAW. "
                  "Re-run with sudo.\n"))
        sys.exit(1)
    except OSError as e:
        return "filtered"
    finally:
        try:
            raw.close()
        except Exception:
            pass


def run_stealth_scan(target: str, ports: list[int], threads: int,
                     timeout: float) -> dict[int, str]:
    if os.geteuid() != 0:
        print(RED("[!] Stealth SYN scan requires root. Re-run with sudo."))
        sys.exit(1)

    try:
        src_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        src_ip = "0.0.0.0"

    section(f"SYN Stealth Scan  →  {target}  ({len(ports)} ports, {threads} threads)")
    results: dict[int, str] = {}
    open_count = 0
    done = 0
    total = len(ports)

    def scan_one(p):
        return p, syn_probe(src_ip, target, p, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_one, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, state = fut.result()
            results[port] = state
            done += 1
            if state == "open":
                open_count += 1
                svc = SERVICE_NAMES.get(port, "unknown")
                result_line(port, state, svc)
            pct = done * 100 // total
            print(f"  {GRAY(f'Progress: {done}/{total}  ({pct}%)')}", end="\r")

    print(" " * 60, end="\r")
    print(f"\n  {GREEN(str(open_count))} open port(s) found (SYN stealth).")
    return results

#  3.  OS FINGERPRINTING
#  Method A: ICMP TTL (ping-like raw socket)
#  Method B: TCP window-size on first open port
#  Method C: TCP timestamp / options parsing
def _icmp_ping(target: str, timeout: float) -> int | None:
    """Send ICMP echo, return TTL from reply or None."""
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket.IPPROTO_ICMP)
        raw.settimeout(timeout)
        # ICMP echo: type=8, code=0
        icmp_id  = random.randint(1, 65535)
        icmp_seq = 1
        header   = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq)
        payload  = b"SDN-Scanner"
        chk      = _checksum(header + payload)
        header   = struct.pack("!BBHHH", 8, 0, chk, icmp_id, icmp_seq)
        pkt      = header + payload

        raw.sendto(pkt, (target, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready = select.select([raw], [], [], max(0, deadline - time.time()))
            if not ready[0]:
                break
            data, _ = raw.recvfrom(1024)
            ttl = data[8]           # TTL field in IP header
            icmp_type = data[20]    # first byte of ICMP payload
            if icmp_type == 0:      # echo reply
                return ttl
        return None
    except PermissionError:
        return None
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _tcp_window_probe(target: str, port: int, timeout: float) -> int | None:
    """Connect TCP and read window size from SYN-ACK (via raw) or skip."""
    # We use a simple connect + getsockopt trick:
    # get SO_RCVBUF as a rough indicator, but we can't read the remote
    # window without raw sockets.  Instead we attempt raw if root.
    if os.geteuid() != 0:
        return None
    try:
        src_ip  = socket.gethostbyname(socket.gethostname())
        src_port = random.randint(1024, 65535)
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)

        pkt = _build_syn_packet(src_ip, target, port, src_port)
        raw.sendto(pkt, (target, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            ready = select.select([raw], [], [], max(0, deadline - time.time()))
            if not ready[0]:
                break
            try:
                data, _ = raw.recvfrom(1024)
            except socket.timeout:
                break
            ip_hdr_len = (data[0] & 0x0F) * 4
            if len(data) < ip_hdr_len + 14:
                continue
            tcp = data[ip_hdr_len:]
            r_src  = struct.unpack("!H", tcp[0:2])[0]
            r_dst  = struct.unpack("!H", tcp[2:4])[0]
            flags  = tcp[13]
            if r_src == port and r_dst == src_port and (flags & 0x12):
                window = struct.unpack("!H", tcp[14:16])[0]
                # Send RST
                try:
                    raw.sendto(pkt, (target, 0))
                except Exception:
                    pass
                return window
        return None
    except Exception:
        return None
    finally:
        try:
            raw.close()
        except Exception:
            pass


def run_os_fingerprint(target: str, open_ports: list[int],
                       timeout: float) -> dict:
    section(f"OS Fingerprinting  →  {target}")
    result = {
        "ttl": None,
        "window": None,
        "guesses": [],
        "confidence": "low",
    }

    # --- TTL probe ---
    ttl = _icmp_ping(target, timeout)
    if ttl is None and os.geteuid() != 0:
        print(YELLOW("  [!] ICMP probe needs root for raw socket. "
                     "Skipping TTL fingerprint."))
    elif ttl is not None:
        result["ttl"] = ttl
        print(f"  TTL from ICMP reply: {BOLD(str(ttl))}")
        for rng, label in OS_TTL_MAP:
            if ttl in rng:
                result["guesses"].append(label)
                print(f"  OS hint (TTL):  {GREEN(label)}")
                break

    # --- TCP window probe ---
    if open_ports:
        probe_port = open_ports[0]
        win = _tcp_window_probe(target, probe_port, timeout)
        if win is not None:
            result["window"] = win
            print(f"  TCP Window (port {probe_port}): {BOLD(str(win))}")
            label = OS_WINDOW_MAP.get(win)
            if label:
                result["guesses"].append(label)
                print(f"  OS hint (TCP win): {GREEN(label)}")

    # --- Confidence ---
    if len(result["guesses"]) >= 2:
        result["confidence"] = "high"
    elif len(result["guesses"]) == 1:
        result["confidence"] = "medium"

    if result["guesses"]:
        unique = list(dict.fromkeys(result["guesses"]))
        conf = result["confidence"]
        print(f"\n  {BOLD('Best guess:')} {GREEN(unique[0])}  "
              f"{DIM(f'(confidence: {conf})')}")
    else:
        print(f"  {YELLOW('Could not determine OS (try running as root)')}")

    return result


def grab_banner(target: str, port: int, timeout: float) -> str | None:
    probe_key  = PORT_PROBE_MAP.get(port, "GENERIC")
    probe_data = BANNER_PROBES.get(probe_key, BANNER_PROBES["GENERIC"])
    if probe_data is not None:
        probe_data = probe_data.replace(b"{host}", target.encode())

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            if probe_data:
                s.sendall(probe_data)
            # Try to recv banner
            s.settimeout(timeout)
            try:
                raw = s.recv(2048)
            except socket.timeout:
                return None
            if not raw:
                return None
            # Clean up to printable ASCII
            banner_text = raw.decode("utf-8", errors="replace")
            banner_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]",
                                 ".", banner_text)
            banner_text = banner_text.strip()
            # Truncate to first meaningful line or 120 chars
            first_line = banner_text.split("\n")[0][:180].strip()
            return first_line if first_line else None
    except Exception:
        return None


def run_banner_grab(target: str, ports: list[int], threads: int,
                    timeout: float) -> dict[int, str | None]:
    section(f"Banner / Service Detection  →  {target}  ({len(ports)} port(s))")
    results: dict[int, str | None] = {}

    def grab_one(p):
        return p, grab_banner(target, p, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(grab_one, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, bnr = fut.result()
            results[port] = bnr
            svc = SERVICE_NAMES.get(port, "unknown")
            if bnr:
                print(f"  {BOLD(str(port)):<12} {YELLOW(svc):<16}  "
                      f"{GREEN('►')} {bnr}")
            else:
                print(f"  {BOLD(str(port)):<12} {YELLOW(svc):<16}  "
                      f"{GRAY('no banner')}")

    grabbed = sum(1 for v in results.values() if v)
    print(f"\n  Banners captured: {GREEN(str(grabbed))} / {len(ports)}")
    return results


def write_report(path: str, target: str, ip: str, scan_results: dict,
                 os_result: dict | None, banners: dict):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 60,
        f"  SDN Scanner Report",
        f"  Target  : {target}  ({ip})",
        f"  Scanned : {ts}",
        "=" * 60,
        "",
    ]

    if scan_results:
        open_ports = [p for p, s in scan_results.items() if s == "open"]
        lines.append(f"OPEN PORTS ({len(open_ports)}):")
        for p in sorted(open_ports):
            svc = SERVICE_NAMES.get(p, "unknown")
            bnr = banners.get(p, "")
            bnr_str = f"  |  {bnr}" if bnr else ""
            lines.append(f"  {p:<8} {svc:<20}{bnr_str}")
        lines.append("")

    if os_result:
        lines.append("OS FINGERPRINT:")
        if os_result.get("ttl"):
            lines.append(f"  TTL         : {os_result['ttl']}")
        if os_result.get("window"):
            lines.append(f"  TCP Window  : {os_result['window']}")
        for g in os_result.get("guesses", []):
            lines.append(f"  Guess       : {g}")
        lines.append(f"  Confidence  : {os_result.get('confidence', 'unknown')}")
        lines.append("")

    lines.append("=" * 60)
    content = "\n".join(lines)
    with open(path, "w") as f:
        f.write(content)
    print(f"\n  {GREEN('✔')} Report saved to: {BOLD(path)}")


# ══════════════════════════════════════════════
#  MAIN CLI
# ══════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Secure SDN Network Scanner
            ──────────────────────────
            Modes:
              common  – TCP connect scan on ~1000 well-known ports (default)
              stealth – SYN half-open scan  (requires root / sudo)
              os      – OS fingerprinting via TTL + TCP window
              banner  – Service banner / version grabbing
              full    – common + os + banner in one run
        """),
        epilog=textwrap.dedent("""\
            Examples:
              python3 scanner.py {ip}
              python3 scanner.py {ip} --mode stealth --ports 1-1024
              python3 scanner.py {ip} --mode full --threads 200 --output rep.txt
              python3 scanner.py {ip} --mode os
              python3 scanner.py {ip} --mode banner --ports 22,80,443,8080
              sudo python3 scanner.py {ip} --mode stealth
        """),
    )
    p.add_argument("target",
                   help="Target IP address or hostname")
    p.add_argument("--mode", "-m",
                   choices=["common", "stealth", "os", "banner", "full"],
                   default="common",
                   help="Scan mode (default: common)")
    p.add_argument("--ports", "-p",
                   default=None,
                   help="Port spec: e.g. 80,443  or  1-1024  (default: top ~1000)")
    p.add_argument("--threads", "-t",
                   type=int, default=150,
                   help="Thread count (default: 150)")
    p.add_argument("--timeout", "-T",
                   type=float, default=1.0,
                   help="Per-port timeout in seconds (default: 1.0)")
    p.add_argument("--output", "-o",
                   default=None,
                   help="Save report to this file")
    p.add_argument("--show-closed", action="store_true",
                   help="Also print closed ports in scan output")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(f"\n  Target  : {BOLD(args.target)}")
    print(f"  Mode    : {CYAN(args.mode)}")
    print(f"  Threads : {args.threads}    Timeout : {args.timeout}s")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    ip = resolve_target(args.target)
    if ip != args.target:
        print(f"  Resolved: {YELLOW(ip)}")

    if args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = FULL_COMMON

    scan_results: dict[int, str] = {}
    os_result: dict | None = None
    banners: dict[int, str | None] = {}

    if args.mode == "common":
        scan_results = run_common_scan(ip, ports, args.threads, args.timeout)

    elif args.mode == "stealth":
        scan_results = run_stealth_scan(ip, ports, args.threads, args.timeout)

    elif args.mode == "os":
        # Do a quick common scan first so we know which ports are open
        print(GRAY("  (Running quick scan to find open ports for OS probing...)"))
        quick = run_common_scan(ip, FULL_COMMON[:256], args.threads, args.timeout)
        open_ports = [p for p, s in quick.items() if s == "open"]
        os_result = run_os_fingerprint(ip, open_ports, args.timeout)

    elif args.mode == "banner":
        # If custom ports given use them, else scan first then grab banners
        if args.ports:
            target_ports = ports
        else:
            print(GRAY("  (Scanning to find open ports first...)"))
            scan_results = run_common_scan(ip, FULL_COMMON, args.threads,
                                           args.timeout)
            target_ports = [p for p, s in scan_results.items() if s == "open"]
        if target_ports:
            banners = run_banner_grab(ip, target_ports, args.threads,
                                      args.timeout)
        else:
            print(YELLOW("  No open ports found to grab banners from."))

    elif args.mode == "full":
        scan_results = run_common_scan(ip, ports, args.threads, args.timeout)
        open_ports = [p for p, s in scan_results.items() if s == "open"]

        os_result = run_os_fingerprint(ip, open_ports, args.timeout)

        if open_ports:
            banners = run_banner_grab(ip, open_ports, args.threads, args.timeout)
        else:
            print(YELLOW("\n  No open ports → skipping banner grab."))

    section("Summary")
    if scan_results:
        open_ports = sorted(p for p, s in scan_results.items() if s == "open")
        print(f"  Open ports ({len(open_ports)}):  "
              f"{', '.join(str(p) for p in open_ports) or 'none'}")

    if os_result and os_result.get("guesses"):
        print(f"  OS guess: {GREEN(os_result['guesses'][0])}  "
              f"[{os_result['confidence']} confidence]")

    if banners:
        grabbed = sum(1 for v in banners.values() if v)
        print(f"  Banners: {grabbed} captured out of {len(banners)} probed")

    if args.output:
        write_report(args.output, args.target, ip, scan_results,
                     os_result, banners)

    print(f"\n{CYAN('─' * 50)}\n")


if __name__ == "__main__":
    main()