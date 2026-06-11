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
import html
import re
import socket
import sqlite3
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
DEFAULT_DB = "sgsn_clients.db"
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


@dataclass
class Sample:
    imsi: str
    ts: int
    online: int
    has_ip: int
    radio_active: int
    ip: str = ""
    state: str = ""
    idle: int | None = None
    tlli: str = ""
    imei: str = ""


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


def init_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS client_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            imsi TEXT NOT NULL,
            imei TEXT,
            ip TEXT,
            state TEXT,
            idle INTEGER,
            tlli TEXT,
            radio_active INTEGER NOT NULL,
            has_ip INTEGER NOT NULL,
            online INTEGER NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS client_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            imsi TEXT NOT NULL,
            event TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS client_last_status (
            imsi TEXT PRIMARY KEY,
            ts INTEGER NOT NULL,
            imei TEXT,
            ip TEXT,
            state TEXT,
            idle INTEGER,
            tlli TEXT,
            radio_active INTEGER NOT NULL,
            has_ip INTEGER NOT NULL,
            online INTEGER NOT NULL
        )
        """
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_samples_imsi_ts ON client_samples(imsi, ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_imsi_ts ON client_events(imsi, ts)")
    db.commit()
    return db


def client_to_sample(client: Client, ts: int) -> Sample:
    return Sample(
        imsi=client.imsi,
        ts=ts,
        online=1,
        has_ip=1 if client.has_ip else 0,
        radio_active=1 if client.radio_active else 0,
        ip=client.ips if client.has_ip else "",
        state=client.state,
        idle=int(client.idle) if client.idle.isdigit() else None,
        tlli=client.tlli,
        imei=client.imei,
    )


def insert_sample(db: sqlite3.Connection, sample: Sample) -> None:
    db.execute(
        """
        INSERT INTO client_samples
            (ts, imsi, imei, ip, state, idle, tlli, radio_active, has_ip, online)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample.ts,
            sample.imsi,
            sample.imei,
            sample.ip,
            sample.state,
            sample.idle,
            sample.tlli,
            sample.radio_active,
            sample.has_ip,
            sample.online,
        ),
    )


def insert_event(db: sqlite3.Connection, ts: int, imsi: str, event: str, old: str = "", new: str = "") -> None:
    db.execute(
        "INSERT INTO client_events (ts, imsi, event, old_value, new_value) VALUES (?, ?, ?, ?, ?)",
        (ts, imsi, event, old, new),
    )


def upsert_last_status(db: sqlite3.Connection, sample: Sample) -> None:
    db.execute(
        """
        INSERT INTO client_last_status
            (imsi, ts, imei, ip, state, idle, tlli, radio_active, has_ip, online)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(imsi) DO UPDATE SET
            ts=excluded.ts,
            imei=excluded.imei,
            ip=excluded.ip,
            state=excluded.state,
            idle=excluded.idle,
            tlli=excluded.tlli,
            radio_active=excluded.radio_active,
            has_ip=excluded.has_ip,
            online=excluded.online
        """,
        (
            sample.imsi,
            sample.ts,
            sample.imei,
            sample.ip,
            sample.state,
            sample.idle,
            sample.tlli,
            sample.radio_active,
            sample.has_ip,
            sample.online,
        ),
    )


def record_snapshot(args: argparse.Namespace) -> int:
    try:
        output = run_command(args.host, args.port, DEFAULT_COMMAND, args.timeout)
    except YateUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Check: sudo systemctl status yate.service", file=sys.stderr)
        return 2

    ts = int(time.time())
    clients = [c for c in parse_clients(output) if c.imsi]
    current = {c.imsi: client_to_sample(c, ts) for c in clients}
    db = init_db(args.db)
    try:
        previous_rows = db.execute(
            """
            SELECT imsi, ts, imei, ip, state, idle, tlli, radio_active, has_ip, online
            FROM client_last_status
            """
        ).fetchall()
        previous = {
            row[0]: Sample(
                imsi=row[0],
                ts=row[1],
                imei=row[2] or "",
                ip=row[3] or "",
                state=row[4] or "",
                idle=row[5],
                tlli=row[6] or "",
                radio_active=row[7],
                has_ip=row[8],
                online=row[9],
            )
            for row in previous_rows
        }

        for imsi, sample in current.items():
            prev = previous.get(imsi)
            insert_sample(db, sample)
            if prev is None:
                insert_event(db, ts, imsi, "CLIENT_SEEN", "", sample.ip)
            else:
                if not prev.online:
                    insert_event(db, ts, imsi, "CLIENT_RETURNED", "", sample.ip)
                if prev.has_ip and not sample.has_ip:
                    insert_event(db, ts, imsi, "PDP_IP_LOST", prev.ip, "")
                if not prev.has_ip and sample.has_ip:
                    insert_event(db, ts, imsi, "PDP_IP_RESTORED", "", sample.ip)
                if prev.ip and sample.ip and prev.ip != sample.ip:
                    insert_event(db, ts, imsi, "IP_CHANGED", prev.ip, sample.ip)
                if prev.tlli and sample.tlli and prev.tlli != sample.tlli:
                    insert_event(db, ts, imsi, "TLLI_CHANGED", prev.tlli, sample.tlli)
                if prev.radio_active and not sample.radio_active:
                    insert_event(db, ts, imsi, "RADIO_INACTIVE", "active", "not_active")
                if not prev.radio_active and sample.radio_active:
                    insert_event(db, ts, imsi, "RADIO_ACTIVE", "not_active", "active")
            upsert_last_status(db, sample)

        for imsi, prev in previous.items():
            if imsi in current or not prev.online:
                continue
            missing = Sample(
                imsi=imsi,
                ts=ts,
                online=0,
                has_ip=0,
                radio_active=0,
                ip="",
                state="missing",
                idle=None,
                tlli=prev.tlli,
                imei=prev.imei,
            )
            insert_sample(db, missing)
            insert_event(db, ts, imsi, "CLIENT_MISSING", prev.ip, "")
            upsert_last_status(db, missing)

        db.commit()
    finally:
        db.close()

    print(f"Recorded {len(current)} clients at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} into {args.db}")
    return 0


def report_history(args: argparse.Namespace) -> int:
    db = init_db(args.db)
    since = int(time.time() - args.since_hours * 3600)
    try:
        rows = db.execute(
            """
            SELECT imsi,
                   COUNT(*) samples,
                   SUM(online) online_samples,
                   SUM(has_ip) ip_samples,
                   SUM(radio_active) radio_samples,
                   MAX(COALESCE(idle, 0)) max_idle,
                   MAX(ts) last_ts
            FROM client_samples
            WHERE ts >= ?
            GROUP BY imsi
            ORDER BY imsi
            """,
            (since,),
        ).fetchall()
        event_rows = db.execute(
            """
            SELECT imsi, event, COUNT(*)
            FROM client_events
            WHERE ts >= ?
            GROUP BY imsi, event
            """,
            (since,),
        ).fetchall()
    finally:
        db.close()

    events: dict[str, dict[str, int]] = {}
    for imsi, event, count in event_rows:
        events.setdefault(imsi, {})[event] = count

    print(f"History report for last {args.since_hours:g}h")
    if not rows:
        print("No samples found.")
        return 1
    header = (
        "IMSI".ljust(18),
        "UP%".rjust(6),
        "IP%".rjust(6),
        "RADIO%".rjust(7),
        "DROPS".rjust(6),
        "IP_LOST".rjust(7),
        "TLLI".rjust(5),
        "MAX_IDLE".rjust(8),
        "LAST_SEEN".ljust(19),
    )
    print("  ".join(header))
    print("-" * 92)
    for imsi, samples, online, ip_samples, radio, max_idle, last_ts in rows:
        ev = events.get(imsi, {})
        up_pct = pct(online, samples)
        ip_pct = pct(ip_samples, samples)
        radio_pct = pct(radio, samples)
        last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts))
        print(
            f"{imsi:<18}  {up_pct:>5.1f}%  {ip_pct:>5.1f}%  {radio_pct:>6.1f}%"
            f"  {ev.get('CLIENT_MISSING', 0):>6}  {ev.get('PDP_IP_LOST', 0):>7}"
            f"  {ev.get('TLLI_CHANGED', 0):>5}  {max_idle:>8}  {last_seen:<19}"
        )
    return 0


def pct(part: int | float | None, total: int | float | None) -> float:
    if not total:
        return 0.0
    return 100.0 * float(part or 0) / float(total)


def write_html_report(args: argparse.Namespace) -> int:
    db = init_db(args.db)
    since = int(time.time() - args.since_hours * 3600)
    try:
        rows = db.execute(
            """
            SELECT ts, imsi, online, has_ip, radio_active, ip, state, idle, tlli
            FROM client_samples
            WHERE ts >= ?
            ORDER BY imsi, ts
            """,
            (since,),
        ).fetchall()
        event_rows = db.execute(
            """
            SELECT ts, imsi, event, old_value, new_value
            FROM client_events
            WHERE ts >= ?
            ORDER BY imsi, ts
            """,
            (since,),
        ).fetchall()
    finally:
        db.close()

    by_imsi: dict[str, list[tuple]] = {}
    for row in rows:
        by_imsi.setdefault(row[1], []).append(row)
    events: dict[str, list[tuple]] = {}
    for row in event_rows:
        events.setdefault(row[1], []).append(row)

    body = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>YateBTS Client Stability</title>",
        "<style>",
        "body{font-family:Arial,sans-serif;background:#101418;color:#e7edf3;margin:24px}",
        "h1{margin:0 0 8px}.muted{color:#9aa7b2}.client{background:#182029;border:1px solid #2c3945;border-radius:10px;padding:14px;margin:12px 0}",
        ".timeline{display:flex;gap:1px;height:22px;margin:8px 0}.seg{flex:1;min-width:3px;border-radius:2px}",
        ".ok{background:#34c759}.idle{background:#ffd60a}.noip{background:#ff9f0a}.down{background:#ff453a}",
        "table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #2c3945;padding:4px 6px;text-align:left}",
        ".pill{display:inline-block;padding:2px 7px;border-radius:999px;background:#273442;margin-right:6px}",
        "</style></head><body>",
        "<h1>YateBTS Client Stability</h1>",
        f"<div class='muted'>Generated {html.escape(time.strftime('%Y-%m-%d %H:%M:%S'))}, window {args.since_hours:g}h</div>",
        "<p><span class='pill' style='background:#34c759'>online+IP+radio</span><span class='pill' style='background:#ffd60a;color:#111'>online+IP idle</span><span class='pill' style='background:#ff9f0a;color:#111'>online no IP</span><span class='pill' style='background:#ff453a'>missing</span></p>",
    ]

    if not by_imsi:
        body.append("<p>No samples found.</p>")
    for imsi, samples in sorted(by_imsi.items()):
        ev = events.get(imsi, [])
        drops = sum(1 for e in ev if e[2] == "CLIENT_MISSING")
        ip_lost = sum(1 for e in ev if e[2] == "PDP_IP_LOST")
        tlli_changes = sum(1 for e in ev if e[2] == "TLLI_CHANGED")
        online = sum(1 for s in samples if s[2])
        ip_samples = sum(1 for s in samples if s[3])
        radio = sum(1 for s in samples if s[4])
        last = samples[-1]
        body.append("<div class='client'>")
        body.append(
            f"<h2>{html.escape(imsi)}</h2><div class='muted'>"
            f"uptime {pct(online, len(samples)):.1f}% | ip {pct(ip_samples, len(samples)):.1f}% | "
            f"radio {pct(radio, len(samples)):.1f}% | drops {drops} | ip_lost {ip_lost} | "
            f"tlli_changes {tlli_changes} | last_ip {html.escape(last[5] or '-')} | "
            f"last_seen {html.escape(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last[0])))}"
            "</div>"
        )
        body.append("<div class='timeline'>")
        for ts, _, online_v, has_ip, radio_active, ip, state, idle, tlli in samples:
            if not online_v:
                cls = "down"
            elif not has_ip:
                cls = "noip"
            elif not radio_active:
                cls = "idle"
            else:
                cls = "ok"
            title = f"{time.strftime('%H:%M:%S', time.localtime(ts))} ip={ip or '-'} state={state or '-'} idle={idle if idle is not None else '-'} tlli={tlli or '-'}"
            body.append(f"<span class='seg {cls}' title='{html.escape(title)}'></span>")
        body.append("</div>")
        if ev:
            body.append("<table><tr><th>Time</th><th>Event</th><th>Old</th><th>New</th></tr>")
            for ts, _, event, old, new in ev[-20:]:
                body.append(
                    "<tr>"
                    f"<td>{html.escape(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)))}</td>"
                    f"<td>{html.escape(event)}</td><td>{html.escape(old or '')}</td><td>{html.escape(new or '')}</td>"
                    "</tr>"
                )
            body.append("</table>")
        body.append("</div>")
    body.append("</body></html>")

    with open(args.html_report, "w", encoding="utf-8") as f:
        f.write("\n".join(body))
    print(f"Wrote {args.html_report}")
    return 0


def once(args: argparse.Namespace) -> int:
    if args.report:
        return report_history(args)
    if args.html_report:
        return write_html_report(args)
    if args.record:
        return record_snapshot(args)
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
    parser.add_argument("--record", action="store_true", help="Record current SGSN snapshot to SQLite")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite history database path")
    parser.add_argument("--report", action="store_true", help="Print per-client stability report from SQLite history")
    parser.add_argument("--html-report", default="", help="Write standalone per-client HTML timeline report")
    parser.add_argument("--since-hours", type=float, default=24.0, help="History window for reports")
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
