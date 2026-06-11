#!/usr/bin/env python3
"""
Show YateBTS GPRS clients by running `mbts sgsn list` over Yate telnet/rmanager.

Examples:
  ./monitor_sgsn_clients.py
  ./monitor_sgsn_clients.py --host 192.168.1.10 --port 5038
  ./monitor_sgsn_clients.py --watch 5
  ./monitor_sgsn_clients.py --raw
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Iterable

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

DEFAULT_COMMAND = "mbts sgsn list"
DIAG_COMMANDS = {
    "sgsn": "mbts sgsn list",
    "gprs": "mbts gprs stat",
    "load": "mbts load",
    "tbf": "mbts gprs list tbf",
    "ch": "mbts gprs list ch",
}


class YateUnavailableError(RuntimeError):
    pass


@dataclass
class Client:
    imsi: str = ""
    imei: str = ""
    ptmsi: str = ""
    tlli: str = ""
    state: str = ""
    age: str = ""
    idle: str = ""
    ms: str = ""
    ips: str = ""

    @property
    def has_ip(self) -> bool:
        return bool(self.ips and self.ips.lower() != "none")

    @property
    def radio_active(self) -> bool:
        return bool(self.ms and self.ms.lower() != "not_active")


@dataclass
class Diagnose:
    clients: list[Client]
    outputs: dict[str, str]
    pdch: int | None = None
    mac_ms: int | None = None
    tbf: int | None = None
    dl_utilization: float | None = None
    sdcch_active: int | None = None
    sdcch_total: int | None = None
    tch_active: int | None = None
    tch_total: int | None = None
    agch_load: str = ""
    pch_load: str = ""
    paging_size: int | None = None


class TelnetSocket:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def close(self) -> None:
        self.sock.close()

    def write_line(self, line: str) -> None:
        self.sock.sendall(line.encode("utf-8") + b"\r\n")

    def read_idle(self, idle_timeout: float, max_wait: float) -> str:
        chunks: list[bytes] = []
        deadline = time.monotonic() + max_wait
        self.sock.settimeout(idle_timeout)
        while time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(strip_telnet_iac(chunk))
        return b"".join(chunks).decode("utf-8", errors="replace")


def strip_telnet_iac(data: bytes) -> bytes:
    """Remove telnet IAC negotiation bytes from a stream chunk."""
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte != IAC:
            out.append(byte)
            i += 1
            continue
        i += 1
        if i >= len(data):
            break
        cmd = data[i]
        i += 1
        if cmd in (DO, DONT, WILL, WONT):
            i += 1
        elif cmd == SB:
            while i + 1 < len(data) and not (data[i] == IAC and data[i + 1] == SE):
                i += 1
            i += 2
        elif cmd == IAC:
            out.append(IAC)
    return bytes(out)


def run_command(host: str, port: int, command: str, timeout: float) -> str:
    try:
        conn = TelnetSocket(host, port, timeout)
    except OSError as exc:
        raise YateUnavailableError(f"Yate is not reachable at {host}:{port}: {exc}") from exc
    try:
        # Drain greeting/banner first. Yate rmanager usually prints it immediately.
        conn.read_idle(idle_timeout=0.3, max_wait=1.5)
        conn.write_line(command)
        output = conn.read_idle(idle_timeout=0.5, max_wait=timeout)
        conn.write_line("quit")
        return output
    finally:
        conn.close()


def run_commands(host: str, port: int, commands: dict[str, str], timeout: float) -> dict[str, str]:
    outputs: dict[str, str] = {}
    try:
        conn = TelnetSocket(host, port, timeout)
    except OSError as exc:
        raise YateUnavailableError(f"Yate is not reachable at {host}:{port}: {exc}") from exc
    try:
        conn.read_idle(idle_timeout=0.3, max_wait=1.5)
        for name, command in commands.items():
            conn.write_line(command)
            outputs[name] = conn.read_idle(idle_timeout=0.5, max_wait=timeout)
        conn.write_line("quit")
        return outputs
    finally:
        conn.close()


def parse_clients(output: str) -> list[Client]:
    clients: list[Client] = []
    for line in output.splitlines():
        if "GMM Context:" not in line:
            continue
        part = line.split("GMM Context:", 1)[1]
        values = dict(re.findall(r"(imsi|ptmsi|tlli|imei|state|age|idle|MS|IPs)=([^\s]+)", part))
        ms = values.get("MS", "")
        if not ms:
            active_ms = re.search(r"\b(MS#[^\s]+)", part)
            if active_ms:
                ms = active_ms.group(1)
        clients.append(
            Client(
                imsi=values.get("imsi", ""),
                imei=values.get("imei", ""),
                ptmsi=values.get("ptmsi", ""),
                tlli=values.get("tlli", ""),
                state=values.get("state", ""),
                age=values.get("age", ""),
                idle=values.get("idle", ""),
                ms=ms,
                ips=values.get("IPs", ""),
            )
        )
    return clients


def print_table(clients: Iterable[Client], show_all: bool) -> None:
    rows = list(clients if show_all else (c for c in clients if c.has_ip))
    total = len(rows)
    pdp_active = sum(1 for c in rows if c.has_ip)
    radio_active = sum(1 for c in rows if c.radio_active)

    print(f"Online clients: {total} | PDP/IP active: {pdp_active} | radio active now: {radio_active}")
    if not rows:
        return

    columns = [
        ("IMSI", 18, lambda c: c.imsi),
        ("IP", 15, lambda c: c.ips),
        ("STATE", 12, lambda c: c.state),
        ("IDLE", 8, lambda c: c.idle),
        ("RADIO", 12, lambda c: c.ms),
        ("TLLI", 12, lambda c: c.tlli),
        ("IMEI", 16, lambda c: c.imei),
    ]
    header = "  ".join(name.ljust(width) for name, width, _ in columns)
    print(header)
    print("-" * len(header))
    for c in rows:
        print("  ".join(trim(getter(c), width).ljust(width) for _, width, getter in columns))


def trim(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)] + "~"


def parse_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_gprs_stat(output: str, diag: Diagnose) -> None:
    current = re.search(r"Current number of\s+PDCH=(\d+)\s+MS=(\d+)\s+TBF=(\d+)", output)
    if current:
        diag.pdch = parse_int(current.group(1))
        diag.mac_ms = parse_int(current.group(2))
        diag.tbf = parse_int(current.group(3))
    util = re.search(r"Downlink utilization=([0-9.]+)", output)
    if util:
        try:
            diag.dl_utilization = float(util.group(1))
        except ValueError:
            pass


def parse_load(output: str, diag: Diagnose) -> None:
    sdcch = re.search(r"SDCCH load:\s*(\d+)/(\d+)", output)
    if sdcch:
        diag.sdcch_active = parse_int(sdcch.group(1))
        diag.sdcch_total = parse_int(sdcch.group(2))
    tch = re.search(r"TCH/F load:\s*(\d+)/(\d+)", output)
    if tch:
        diag.tch_active = parse_int(tch.group(1))
        diag.tch_total = parse_int(tch.group(2))
    agch_pch = re.search(r"AGCH/PCH load:\s*([^,\s]+),([^\s]+)", output)
    if agch_pch:
        diag.agch_load = agch_pch.group(1)
        diag.pch_load = agch_pch.group(2)
    paging = re.search(r"Paging table size:\s*(\d+)", output)
    if paging:
        diag.paging_size = parse_int(paging.group(1))


def count_lines(output: str, token: str) -> int:
    return sum(1 for line in output.splitlines() if token in line)


def build_diagnose(args: argparse.Namespace) -> Diagnose | None:
    try:
        outputs = run_commands(args.host, args.port, DIAG_COMMANDS, args.timeout)
    except YateUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Check: sudo systemctl status yate.service", file=sys.stderr)
        return None
    diag = Diagnose(clients=parse_clients(outputs.get("sgsn", "")), outputs=outputs)
    parse_gprs_stat(outputs.get("gprs", ""), diag)
    parse_load(outputs.get("load", ""), diag)
    return diag


def print_diagnose(args: argparse.Namespace) -> int:
    diag = build_diagnose(args)
    if diag is None:
        return 2

    contexts = len(diag.clients)
    pdp_active = sum(1 for c in diag.clients if c.has_ip)
    no_ip = contexts - pdp_active
    radio_active = sum(1 for c in diag.clients if c.radio_active)
    idles = [int(c.idle) for c in diag.clients if c.idle.isdigit()]
    max_idle = max(idles) if idles else None
    avg_idle = sum(idles) / len(idles) if idles else None
    listed_tbf = count_lines(diag.outputs.get("tbf", ""), "TBF#")
    listed_ch = count_lines(diag.outputs.get("ch", ""), "PDCH")

    warnings: list[tuple[str, str]] = []
    if contexts == 0:
        warnings.append(("CRIT", "no SGSN GMM contexts parsed; clients may be detached or command output changed"))
    if args.expected_clients and pdp_active < args.expected_clients:
        warnings.append(("WARN", f"PDP/IP active {pdp_active} < expected {args.expected_clients}"))
    if contexts and no_ip / contexts >= 0.2:
        warnings.append(("WARN", f"{no_ip}/{contexts} SGSN contexts have no IP"))
    if diag.dl_utilization is not None and diag.dl_utilization >= args.warn_utilization:
        warnings.append(("WARN", f"GPRS downlink utilization is high: {diag.dl_utilization:.1f}"))
    if diag.tbf is not None and diag.tbf >= args.warn_tbf:
        warnings.append(("WARN", f"active TBF count is high: {diag.tbf}"))
    if diag.mac_ms is not None and pdp_active and diag.mac_ms == 0:
        warnings.append(("WARN", "PDP clients exist but MAC MS count is 0; radio side is idle or stalled"))
    if diag.pdch is not None and diag.pdch == 0 and pdp_active:
        warnings.append(("CRIT", "PDP clients exist but no active PDCH"))
    if diag.sdcch_total and diag.sdcch_active is not None and diag.sdcch_active / diag.sdcch_total >= 0.8:
        warnings.append(("WARN", f"SDCCH load is high: {diag.sdcch_active}/{diag.sdcch_total}"))
    if diag.tch_total and diag.tch_active is not None and diag.tch_active / diag.tch_total >= 0.8:
        warnings.append(("WARN", f"TCH/F load is high: {diag.tch_active}/{diag.tch_total}"))
    if diag.paging_size is not None and diag.paging_size >= args.warn_paging:
        warnings.append(("WARN", f"paging table is high: {diag.paging_size}"))
    if max_idle is not None and max_idle >= args.warn_idle:
        warnings.append(("WARN", f"max SGSN idle is high: {max_idle}s"))

    severity = "OK"
    if any(level == "CRIT" for level, _ in warnings):
        severity = "CRIT"
    elif warnings:
        severity = "WARN"

    print(f"Status: {severity}")
    print("SGSN:")
    print(f"  contexts: {contexts}")
    print(f"  pdp_ip_active: {pdp_active}")
    print(f"  no_ip: {no_ip}")
    print(f"  radio_active_now: {radio_active}")
    if max_idle is not None:
        print(f"  idle: avg={avg_idle:.1f}s max={max_idle}s")
    print("GPRS:")
    print(f"  pdch: {value_or_unknown(diag.pdch)}")
    print(f"  mac_ms: {value_or_unknown(diag.mac_ms)}")
    print(f"  tbf: {value_or_unknown(diag.tbf)}")
    print(f"  listed_tbf: {listed_tbf}")
    print(f"  listed_pdch_lines: {listed_ch}")
    print(f"  downlink_utilization: {value_or_unknown(diag.dl_utilization)}")
    print("BTS:")
    print(f"  sdcch: {ratio_or_unknown(diag.sdcch_active, diag.sdcch_total)}")
    print(f"  tch_f: {ratio_or_unknown(diag.tch_active, diag.tch_total)}")
    print(f"  agch_pch: {diag.agch_load or '?'},{diag.pch_load or '?'}")
    print(f"  paging_table: {value_or_unknown(diag.paging_size)}")
    print("Verdict:")
    if warnings:
        for level, msg in warnings:
            print(f"  {level}: {msg}")
    else:
        print("  OK: no obvious bottleneck from parsed counters")
    return 0 if severity == "OK" else (2 if severity == "CRIT" else 1)


def value_or_unknown(value: object) -> str:
    return "?" if value is None else str(value)


def ratio_or_unknown(active: int | None, total: int | None) -> str:
    if active is None or total is None:
        return "?/?"
    return f"{active}/{total}"


def once(args: argparse.Namespace) -> int:
    if args.diagnose:
        return print_diagnose(args)
    try:
        output = run_command(args.host, args.port, args.command, args.timeout)
    except YateUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Check: sudo systemctl status yate.service", file=sys.stderr)
        return 2
    clients = parse_clients(output)
    if args.raw:
        print(output.rstrip())
        return 0
    if not clients:
        print("No GMM Context entries parsed. Raw command output follows:\n")
        print(output.rstrip())
        return 1
    print_table(clients, show_all=args.all)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor YateBTS SGSN clients over telnet")
    parser.add_argument("--host", default="127.0.0.1", help="Yate telnet/rmanager host")
    parser.add_argument("--port", type=int, default=5038, help="Yate telnet/rmanager port")
    parser.add_argument("--command", default=DEFAULT_COMMAND, help="Command to execute")
    parser.add_argument("--timeout", type=float, default=5.0, help="Command read timeout in seconds")
    parser.add_argument("--watch", type=float, default=0.0, help="Refresh interval in seconds")
    parser.add_argument("--all", action="store_true", help="Show all GMM contexts, including IPs=none")
    parser.add_argument("--raw", action="store_true", help="Print raw command output")
    parser.add_argument("--diagnose", action="store_true", help="Collect SGSN/GPRS/BTS counters and print OK/WARN/CRIT")
    parser.add_argument("--expected-clients", type=int, default=0, help="Warn if PDP/IP active clients are below this")
    parser.add_argument("--warn-utilization", type=float, default=80.0, help="Warn if GPRS downlink utilization reaches this value")
    parser.add_argument("--warn-tbf", type=int, default=12, help="Warn if active TBF count reaches this value")
    parser.add_argument("--warn-idle", type=int, default=300, help="Warn if any SGSN context idle time reaches this many seconds")
    parser.add_argument("--warn-paging", type=int, default=10, help="Warn if paging table size reaches this value")
    args = parser.parse_args()

    if args.watch <= 0:
        return once(args)

    while True:
        print("\033[2J\033[H", end="")
        print(time.strftime("%Y-%m-%d %H:%M:%S"))
        try:
            rc = once(args)
        except KeyboardInterrupt:
            return 130
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            rc = 1
        time.sleep(args.watch)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
