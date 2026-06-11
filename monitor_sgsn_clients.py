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
    conn = TelnetSocket(host, port, timeout)
    try:
        # Drain greeting/banner first. Yate rmanager usually prints it immediately.
        conn.read_idle(idle_timeout=0.3, max_wait=1.5)
        conn.write_line(command)
        output = conn.read_idle(idle_timeout=0.5, max_wait=timeout)
        conn.write_line("quit")
        return output
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


def once(args: argparse.Namespace) -> int:
    output = run_command(args.host, args.port, args.command, args.timeout)
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
