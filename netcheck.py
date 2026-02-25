#!/usr/bin/env python3
"""
NetCheck (lean) — Windows-friendly network checks + persistent inventory CSV.

Each run:
- Check ONE device (--target) OR many from a file (--input)
- DNS resolve (best effort) + reverse lookup (best effort)
- Ping
- TCP port connect checks
- Update ONE inventory CSV:
  - add new devices
  - update existing devices
  - set last_checked timestamp
  - sort so most recently checked are at the TOP

Key design choices:
- device_key uses HOSTNAME as the source of truth when available.
  This prevents duplicate entries if the IP changes over time.
- inventory writes are atomic (write .tmp then os.replace()).
- TCP timeout is derived from --timeout to avoid false negatives on slower networks.
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


# ---- Port presets tuned for your environment ----
PORT_PRESETS: Dict[str, List[int]] = {
    "printers": [9100, 631, 80, 443],
    "3dprinters": [80, 5000, 8080],
    "servers_switches": [22, 443, 23],
    "mixed": [9100, 631, 80, 443, 5000, 8080, 22, 23],
}

# ---- Minimal CSV schema ----
FIELDS = [
    "device_key",     # hostname (preferred) or ip if hostname unknown
    "input_target",   # what you typed / what was in the file
    "hostname",       # normalized hostname if provided
    "ip",
    "reverse_dns",
    "ping_ok",
    "rtt_ms",
    "open_ports",
    "notes",
    "first_seen",
    "last_checked",
]


@dataclass
class Result:
    input_target: str
    hostname: str
    ip: str
    reverse_dns: str
    ping_ok: bool
    rtt_ms: str
    open_ports: str
    notes: str


def read_targets(path: Path) -> List[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        return False


def normalize_hostname(s: str) -> str:
    return s.strip().lower()


def resolve(target: str) -> Tuple[str, str, str, str]:
    """
    Returns (hostname, ip, reverse_dns, note)
    - If target is hostname: hostname=normalized target, attempt DNS to get ip
    - If target is IP: hostname="", ip=target
    Reverse DNS is best-effort.
    """
    t = target.strip()
    hostname = "" if is_ip(t) else normalize_hostname(t)

    ip = ""
    try:
        ip = t if is_ip(t) else socket.gethostbyname(t)
    except Exception as e:
        return hostname, "", "", f"DNS resolve failed: {e}"

    rev = ""
    try:
        rev = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return hostname, ip, rev, ""


def ping(ip: str, timeout_s: int) -> Tuple[bool, str, str]:
    """
    Returns (ok, rtt_ms_best_effort, note)
    Uses platform ping:
      Windows: ping -n 1 -w <ms>
    RTT here is "wall clock" for the ping command (lean + consistent).
    """
    if not ip:
        return False, "", "No IP"

    sysname = platform.system().lower()
    if sysname == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        start = time.time()
        p = subprocess.run(cmd, capture_output=True, text=True)
        elapsed_ms = int((time.time() - start) * 1000)
        if p.returncode == 0:
            return True, str(elapsed_ms), ""
        return False, "", (p.stderr or p.stdout).strip()
    except Exception as e:
        return False, "", str(e)


def tcp_open(ip: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def make_device_key(hostname: str, ip: str) -> str:
    """
    Hostname-first keying:
    - If hostname exists, it is the unique ID (stable across IP changes).
    - If you provided only an IP, key by IP.
    """
    return hostname if hostname else ip


def check_one(target: str, ports: List[int], ping_timeout: int, tcp_timeout: float) -> Result:
    hostname, ip, rev, note = resolve(target)
    ping_ok, rtt_ms, ping_note = ping(ip, ping_timeout) if ip else (False, "", "No IP")

    open_ports: List[str] = []
    if ip:
        for p in ports:
            if tcp_open(ip, p, tcp_timeout):
                open_ports.append(str(p))

    notes = note
    if not notes and not ping_ok:
        notes = f"Ping failed: {ping_note}"

    return Result(
        input_target=target.strip(),
        hostname=hostname,
        ip=ip,
        reverse_dns=rev,
        ping_ok=ping_ok,
        rtt_ms=rtt_ms,
        open_ports=",".join(open_ports),
        notes=notes,
    )


def load_inventory(path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load existing inventory keyed by device_key.
    Backward compatible: if device_key missing, rebuild it hostname-first.
    """
    if not path.exists():
        return {}

    inv: Dict[str, Dict[str, str]] = {}
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            dk = (row.get("device_key") or "").strip()
            hostname = (row.get("hostname") or "").strip().lower()
            ip = (row.get("ip") or "").strip()

            if not dk:
                dk = make_device_key(hostname, ip)
                row["device_key"] = dk

            inv[dk] = row
    return inv


def upsert(inv: Dict[str, Dict[str, str]], results: List[Result]) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for r in results:
        dk = make_device_key(r.hostname, r.ip)
        if not dk:
            # If we couldn't resolve at all, fall back to input target as last resort
            dk = normalize_hostname(r.input_target) if not is_ip(r.input_target) else r.input_target.strip()

        row = inv.get(dk)
        if row is None:
            row = {c: "" for c in FIELDS}
            row["device_key"] = dk
            row["first_seen"] = now
            inv[dk] = row

        row["input_target"] = r.input_target
        row["hostname"] = r.hostname
        row["ip"] = r.ip
        row["reverse_dns"] = r.reverse_dns
        row["ping_ok"] = str(r.ping_ok)
        row["rtt_ms"] = r.rtt_ms
        row["open_ports"] = r.open_ports
        row["notes"] = r.notes
        row["last_checked"] = now


def write_inventory_atomic(path: Path, inv: Dict[str, Dict[str, str]]) -> None:
    """
    Atomic write:
    - write to path.tmp
    - os.replace(tmp, path) so you never end up with a half-written inventory
    Sorted by last_checked desc so most recently checked are at the top.
    """
    rows = list(inv.values())

    def parse_ts(s: str) -> datetime:
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.min

    rows.sort(key=lambda row: parse_ts(row.get("last_checked", "")), reverse=True)

    tmp_path = Path(str(path) + ".tmp")
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({c: row.get(c, "") for c in FIELDS})

    os.replace(tmp_path, path)


def main() -> int:
    ap = argparse.ArgumentParser(description="NetCheck (lean) - persistent CSV inventory for quick checks.")
    ap.add_argument("--target", help="Single hostname/IP.")
    ap.add_argument("--input", help="File with targets (one per line).")
    ap.add_argument("--preset", choices=list(PORT_PRESETS.keys()), default="mixed", help="Port preset to use.")
    ap.add_argument("--ports", nargs="*", type=int, help="Explicit ports (overrides preset).")
    ap.add_argument("--timeout", type=int, default=2, help="Ping timeout seconds (also influences TCP timeout).")
    ap.add_argument("--tcp-timeout", type=float, default=0.0,
                    help="TCP connect timeout seconds (default: derived from --timeout).")
    ap.add_argument("--workers", type=int, default=12, help="Parallel workers for file input.")
    ap.add_argument("--inventory", default="netcheck_inventory.csv", help="Inventory CSV path.")
    args = ap.parse_args()

    if args.target:
        targets = [args.target.strip()]
    elif args.input:
        targets = read_targets(Path(args.input))
    else:
        print("Provide --target <host/ip> or --input <file>", file=sys.stderr)
        return 2

    if not targets:
        print("No targets to check.", file=sys.stderr)
        return 2

    ports = args.ports if args.ports else PORT_PRESETS[args.preset]

    # TCP timeout: tie it to ping timeout to avoid false negatives on slower links.
    # Rule of thumb: ~50% of ping timeout, with a minimum floor.
    tcp_timeout = args.tcp_timeout if args.tcp_timeout > 0 else max(0.8, args.timeout * 0.5)

    results: List[Result] = []
    if len(targets) == 1:
        results.append(check_one(targets[0], ports, args.timeout, tcp_timeout))
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(check_one, t, ports, args.timeout, tcp_timeout): t for t in targets}
            for fut in as_completed(futs):
                results.append(fut.result())

    inv_path = Path(args.inventory)
    inv = load_inventory(inv_path)
    upsert(inv, results)
    write_inventory_atomic(inv_path, inv)

    # Print what you just checked (these will be the newest rows in the CSV)
    for r in results:
        key = make_device_key(r.hostname, r.ip) or r.input_target
        print(f"{key} -> {r.ip} | ping={'OK' if r.ping_ok else 'NO'} | open={r.open_ports or '-'} | {r.notes}")

    print(f"Updated: {inv_path} (tracked devices: {len(inv)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())