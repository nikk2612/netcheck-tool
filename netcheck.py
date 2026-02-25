#!/usr/bin/env python3
"""
NetCheck - Windows-friendly network preflight tuned for:
  - Printers (9100/raw, 631/IPP, 80/443)
  - 3D Printers / OctoPrint (80, 5000, 8080)
  - Servers / Switches (22, 23, 443, 161/NOTE_UDP)

Features:
- DNS forward + reverse check
- ICMP ping (uses platform ping)
- Parallel checks across targets
- TCP port check + optional banner/title grabs for HTTP/SSH
- Optional traceroute (uses tracert on Windows)
- Exports CSV and Markdown
"""

from __future__ import annotations
import argparse
import csv
import platform
import socket
import subprocess
import sys
import time
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- Configuration: default ports for each device-type ----------
DEFAULT_PORTS = {
    "printers": [9100, 631, 80, 443],           # raw printing, IPP, web UI
    "3dprinters": [80, 5000, 8080],             # OctoPrint (5000), web UIs
    "servers_switches": [22, 23, 443, 161],     # SSH, Telnet, HTTPS, SNMP (UDP note)
}
# Flatten default ports into a sensible default order for general checks:
DEFAULT_FLATTENED = sorted({p for plist in DEFAULT_PORTS.values() for p in plist})

# ---------- Data model ----------
@dataclass
class CheckResult:
    target: str
    resolved_ip: str
    reverse_name: str
    dns_ok: bool
    ping_ok: bool
    rtt_ms: str
    open_ports: str
    closed_ports: str
    http_title: str
    ssh_banner: str
    notes: str

# ---------- Utilities ----------
def read_targets(path: Path) -> List[str]:
    raw = path.read_text(encoding="utf-8").splitlines()
    targets = [line.strip() for line in raw if line.strip() and not line.strip().startswith("#")]
    return targets

def is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        return False

def dns_lookup(target: str) -> (str, str, bool, str):
    try:
        if is_ip(target):
            ip = target
            try:
                rev = socket.gethostbyaddr(ip)[0]
                return ip, rev, True, ""
            except Exception as e:
                return ip, "", False, f"Reverse DNS failed: {e}"
        else:
            ip = socket.gethostbyname(target)
            rev = ""
            ok = True
            err = ""
            try:
                rev = socket.gethostbyaddr(ip)[0]
            except Exception as e:
                ok = False
                err = f"Reverse DNS failed: {e}"
            return ip, rev, ok, err
    except Exception as e:
        return "", "", False, f"DNS lookup failed: {e}"

def ping(ip: str, timeout_s: int = 2) -> (bool, str, str):
    if not ip:
        return False, "", "No IP"
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        start = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed_ms = int((time.time() - start) * 1000)
        if proc.returncode == 0:
            return True, str(elapsed_ms), ""
        else:
            # try to parse RTT from output if possible (best-effort)
            out = proc.stdout + proc.stderr
            m = re.search(r'time[=<]\s*([\d\.]+)\s*ms', out)
            if m:
                return True, m.group(1), ""
            return False, "", (proc.stderr or proc.stdout).strip()
    except Exception as e:
        return False, "", str(e)

def tcp_port_check_with_banner(ip: str, port: int, timeout_s: float = 1.0) -> (bool, str):
    """
    Attempts TCP connect; for certain ports try to read banner or HTTP title.
    Returns (is_open, banner_or_title)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as s:
            s.settimeout(timeout_s)
            banner = ""
            # SSH (22) banner grab
            if port == 22:
                try:
                    banner = s.recv(256).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
            # HTTP-like ports: send a simple HEAD to get a response/title
            if port in (80, 443, 8080, 5000):
                try:
                    # If TLS (443) we'd need ssl.wrap_socket; instead we send HOST header and hope redirect/response helps on non-TLS admin pages.
                    req = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(ip)
                    s.sendall(req.encode())
                    resp = s.recv(4096).decode(errors="ignore")
                    # try to extract <title> if any
                    m = re.search(r"<title>(.*?)</title>", resp, re.IGNORECASE | re.DOTALL)
                    if m:
                        banner = m.group(1).strip()
                    else:
                        # fallback: extract Server header or first line
                        lines = resp.splitlines()
                        for L in lines[:10]:
                            if "Server:" in L or "HTTP/" in L:
                                banner = L.strip()
                                break
                except Exception:
                    pass
            return True, banner
    except Exception:
        return False, ""

def traceroute_cmd(ip: str, max_hops: int = 12) -> (bool, str):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), ip]
    else:
        cmd = ["traceroute", "-m", str(max_hops), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        ok = proc.returncode == 0
        out = (proc.stdout or proc.stderr or "").strip()
        return ok, out
    except Exception as e:
        return False, f"Traceroute error: {e}"

# ---------- Worker logic (per-target) ----------
def check_target(target: str, ports: List[int], ping_timeout: int) -> (CheckResult, str):
    ip, rev, dns_ok, dns_err = dns_lookup(target)
    ping_ok, rtt_ms, ping_err = ping(ip, timeout_s=ping_timeout) if ip else (False, "", "No IP")
    open_ports = []
    closed_ports = []
    http_titles = []
    ssh_banner = ""
    notes = ""

    for p in ports:
        # We will try TCP port check; note: port 161 is normally UDP (SNMP) — TCP check may not be meaningful.
        is_open, banner = tcp_port_check_with_banner(ip, p, timeout_s=1.0) if ip else (False, "")
        if is_open:
            open_ports.append(str(p))
            if p in (80, 8080, 5000, 443):
                if banner:
                    http_titles.append(f"{p}:{banner}")
            if p == 22 and banner:
                ssh_banner = banner
        else:
            closed_ports.append(str(p))

    if not ip:
        notes = dns_err or "Could not resolve"
    elif not dns_ok:
        notes = dns_err
    elif not ping_ok:
        notes = f"Ping failed: {ping_err}"

    result = CheckResult(
        target=target,
        resolved_ip=ip,
        reverse_name=rev,
        dns_ok=dns_ok,
        ping_ok=ping_ok,
        rtt_ms=rtt_ms,
        open_ports=",".join(open_ports),
        closed_ports=",".join(closed_ports),
        http_title=" | ".join(http_titles),
        ssh_banner=ssh_banner,
        notes=notes
    )
    return result, ""  # second return reserved for trace text when invoked externally

# ---------- Output helpers ----------
def to_csv(results: List[CheckResult], path: Path):
    if not results:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))

def to_markdown(results: List[CheckResult], ports: List[int], traces: Dict[str,str], include_trace: bool) -> str:
    lines = []
    lines.append("# NetCheck Report\n")
    lines.append(f"Checked ports: {', '.join(map(str, ports)) if ports else 'None'}  \n")
    lines.append("| Target | IP | DNS OK | Ping | RTT (ms) | Open Ports | HTTP Titles | SSH Banner | Notes |")
    lines.append("|---|---:|:---:|:---:|---:|---|---|---|---|")
    for r in results:
        lines.append(f"| {r.target} | {r.resolved_ip} | {'✅' if r.dns_ok else '❌'} | {'✅' if r.ping_ok else '❌'} | {r.rtt_ms or ''} | {r.open_ports or ''} | {r.http_title or ''} | {r.ssh_banner or ''} | {r.notes or ''} |")
    if include_trace:
        lines.append("\n## Traceroutes\n")
        for t, txt in traces.items():
            lines.append(f"### {t}\n")
            lines.append("```")
            lines.append(txt)
            lines.append("```")
    lines.append("")
    return "\n".join(lines)

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="NetCheck - Windows-friendly preflight checks (printers, 3D printers, servers/switches).")
    ap.add_argument("--input", required=True, help="Path to file with targets (one hostname or IP per line).")
    ap.add_argument("--device-type", choices=["printers","3dprinters","servers_switches","mixed"], default="mixed",
                    help="Choose default port set tuned for your devices. 'mixed' uses a combined default.")
    ap.add_argument("--ports", nargs="*", type=int, default=None, help="Explicit list of ports to check (overrides device-type).")
    ap.add_argument("--timeout", type=int, default=2, help="Ping timeout seconds (default: 2).")
    ap.add_argument("--csv", default="", help="Optional CSV output path.")
    ap.add_argument("--md", default="", help="Optional Markdown output path.")
    ap.add_argument("--trace", action="store_true", help="Include traceroute (slower).")
    ap.add_argument("--workers", type=int, default=10, help="Number of parallel workers (default: 10).")
    args = ap.parse_args()

    targets = read_targets(Path(args.input))
    if not targets:
        print("No targets found in", args.input, file=sys.stderr)
        return 2

    if args.ports:
        ports = args.ports
    else:
        if args.device_type == "mixed":
            ports = DEFAULT_FLATTENED
        else:
            ports = DEFAULT_PORTS[args.device_type]

    results = []
    traces = {}

    print(f"Checking {len(targets)} targets with ports: {ports} (workers={args.workers})")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_to_target = {ex.submit(check_target, t, ports, args.timeout): t for t in targets}
        for fut in as_completed(future_to_target):
            t = future_to_target[fut]
            try:
                res, _ = fut.result()
                results.append(res)
                # Optionally do traceroute serially (slower) if requested
                if args.trace and res.resolved_ip:
                    ok, tr = traceroute_cmd(res.resolved_ip)
                    traces[t] = tr
                # Provide brief console status line
                print(f"[{len(results)}/{len(targets)}] {res.target} -> {res.resolved_ip} ping:{'OK' if res.ping_ok else 'NO'} open:{res.open_ports or 'none'}")
            except Exception as e:
                print(f"Error checking {t}: {e}", file=sys.stderr)

    # write CSV & Markdown
    if args.csv:
        to_csv(results, Path(args.csv))
        print("Wrote CSV:", args.csv)
    md_text = to_markdown(results, ports, traces, args.trace)
    if args.md:
        Path(args.md).write_text(md_text, encoding="utf-8")
        print("Wrote Markdown:", args.md)
    else:
        print(md_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())