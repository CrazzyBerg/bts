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
import threading
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
    client_id: str
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

    def read_some(self, timeout: float) -> str:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(8192)
        except socket.timeout:
            return ""
        if not data:
            raise EOFError("telnet connection closed")
        return strip_telnet_iac(data).decode("utf-8", errors="replace")


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
            client_id TEXT,
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
            client_id TEXT,
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
            client_id TEXT PRIMARY KEY,
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
        CREATE TABLE IF NOT EXISTS imsi_imei_map (
            imsi TEXT PRIMARY KEY,
            imei TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            source TEXT NOT NULL
        )
        """
    )
    ensure_column(db, "client_samples", "client_id", "TEXT")
    ensure_column(db, "client_events", "client_id", "TEXT")
    ensure_column(db, "client_last_status", "client_id", "TEXT")
    ensure_column(db, "client_last_status", "imsi", "TEXT")
    db.execute("UPDATE client_samples SET client_id = COALESCE(NULLIF(imei, ''), imsi) WHERE client_id IS NULL")
    db.execute("UPDATE client_events SET client_id = imsi WHERE client_id IS NULL")
    db.execute("UPDATE client_last_status SET client_id = COALESCE(NULLIF(imei, ''), imsi) WHERE client_id IS NULL")
    db.execute("UPDATE client_last_status SET imsi = client_id WHERE imsi IS NULL")
    db.execute("CREATE INDEX IF NOT EXISTS idx_samples_imsi_ts ON client_samples(imsi, ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_samples_client_ts ON client_samples(client_id, ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_imsi_ts ON client_events(imsi, ts)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_client_ts ON client_events(client_id, ts)")
    db.commit()
    return db


def ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def lookup_imei(db: sqlite3.Connection, imsi: str) -> str:
    row = db.execute("SELECT imei FROM imsi_imei_map WHERE imsi = ?", (imsi,)).fetchone()
    return row[0] if row else ""


def resolve_client_id(db: sqlite3.Connection, imsi: str, imei: str) -> str:
    resolved_imei = imei or lookup_imei(db, imsi)
    return resolved_imei or imsi


def update_imsi_imei_map(db: sqlite3.Connection, ts: int, imsi: str, imei: str, source: str) -> None:
    if not (imsi and imei):
        return
    row = db.execute("SELECT imei FROM imsi_imei_map WHERE imsi = ?", (imsi,)).fetchone()
    if row and row[0] != imei:
        insert_event(db, ts, imei, imsi, "IMEI_MAPPING_CHANGED", row[0], imei)
    db.execute(
        """
        INSERT INTO imsi_imei_map (imsi, imei, first_seen, last_seen, source)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(imsi) DO UPDATE SET
            imei=excluded.imei,
            last_seen=excluded.last_seen,
            source=excluded.source
        """,
        (imsi, imei, ts, ts, source),
    )
    db.execute("UPDATE client_samples SET client_id = ?, imei = ? WHERE imsi = ?", (imei, imei, imsi))
    db.execute("UPDATE client_events SET client_id = ? WHERE imsi = ?", (imei, imsi))


def client_to_sample(client: Client, ts: int, db: sqlite3.Connection) -> Sample:
    if client.imei:
        update_imsi_imei_map(db, ts, client.imsi, client.imei, "sgsn")
    imei = client.imei or lookup_imei(db, client.imsi)
    client_id = imei or client.imsi
    return Sample(
        client_id=client_id,
        imsi=client.imsi,
        ts=ts,
        online=1,
        has_ip=1 if client.has_ip else 0,
        radio_active=1 if client.radio_active else 0,
        ip=client.ips if client.has_ip else "",
        state=client.state,
        idle=int(client.idle) if client.idle.isdigit() else None,
        tlli=client.tlli,
        imei=imei,
    )


def insert_sample(db: sqlite3.Connection, sample: Sample) -> None:
    db.execute(
        """
        INSERT INTO client_samples
            (ts, client_id, imsi, imei, ip, state, idle, tlli, radio_active, has_ip, online)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample.ts,
            sample.client_id,
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


def insert_event(db: sqlite3.Connection, ts: int, client_id: str, imsi: str, event: str, old: str = "", new: str = "") -> None:
    db.execute(
        "INSERT INTO client_events (ts, client_id, imsi, event, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, client_id, imsi, event, old, new),
    )


def upsert_last_status(db: sqlite3.Connection, sample: Sample) -> None:
    db.execute(
        "DELETE FROM client_last_status WHERE client_id = ? OR imsi = ?",
        (sample.client_id, sample.imsi),
    )
    db.execute(
        """
        INSERT INTO client_last_status
            (client_id, ts, imsi, imei, ip, state, idle, tlli, radio_active, has_ip, online)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample.client_id,
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


def record_snapshot(args: argparse.Namespace) -> int:
    try:
        output = run_command(args.host, args.port, DEFAULT_COMMAND, args.timeout)
    except YateUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Check: sudo systemctl status yate.service", file=sys.stderr)
        return 2

    ts = int(time.time())
    clients = [c for c in parse_clients(output) if c.imsi]
    db = init_db(args.db)
    try:
        current = {}
        for client in clients:
            sample = client_to_sample(client, ts, db)
            current[sample.client_id] = sample
        previous_rows = db.execute(
            """
            SELECT client_id, imsi, ts, imei, ip, state, idle, tlli, radio_active, has_ip, online
            FROM client_last_status
            """
        ).fetchall()
        previous = {
            row[0]: Sample(
                client_id=row[0],
                imsi=row[1],
                ts=row[2],
                imei=row[3] or "",
                ip=row[4] or "",
                state=row[5] or "",
                idle=row[6],
                tlli=row[7] or "",
                radio_active=row[8],
                has_ip=row[9],
                online=row[10],
            )
            for row in previous_rows
        }

        for client_id, sample in current.items():
            prev = previous.get(client_id)
            insert_sample(db, sample)
            if prev is None:
                insert_event(db, ts, sample.client_id, sample.imsi, "CLIENT_SEEN", "", sample.ip)
            else:
                if prev.imsi and sample.imsi and prev.imsi != sample.imsi:
                    insert_event(db, ts, sample.client_id, sample.imsi, "SIM_SWITCHED", prev.imsi, sample.imsi)
                if not prev.online:
                    insert_event(db, ts, sample.client_id, sample.imsi, "CLIENT_RETURNED", "", sample.ip)
                if prev.has_ip and not sample.has_ip:
                    insert_event(db, ts, sample.client_id, sample.imsi, "PDP_IP_LOST", prev.ip, "")
                if not prev.has_ip and sample.has_ip:
                    insert_event(db, ts, sample.client_id, sample.imsi, "PDP_IP_RESTORED", "", sample.ip)
                if prev.ip and sample.ip and prev.ip != sample.ip:
                    insert_event(db, ts, sample.client_id, sample.imsi, "IP_CHANGED", prev.ip, sample.ip)
                if prev.tlli and sample.tlli and prev.tlli != sample.tlli:
                    insert_event(db, ts, sample.client_id, sample.imsi, "TLLI_CHANGED", prev.tlli, sample.tlli)
                if prev.radio_active and not sample.radio_active:
                    insert_event(db, ts, sample.client_id, sample.imsi, "RADIO_INACTIVE", "active", "not_active")
                if not prev.radio_active and sample.radio_active:
                    insert_event(db, ts, sample.client_id, sample.imsi, "RADIO_ACTIVE", "not_active", "active")
            upsert_last_status(db, sample)

        for client_id, prev in previous.items():
            if client_id in current or not prev.online:
                continue
            missing = Sample(
                client_id=prev.client_id,
                imsi=prev.imsi,
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
            insert_event(db, ts, missing.client_id, missing.imsi, "CLIENT_MISSING", prev.ip, "")
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
            SELECT client_id,
                   GROUP_CONCAT(DISTINCT imsi) imsis,
                   MAX(imei) imei,
                   COUNT(*) samples,
                   SUM(online) online_samples,
                   SUM(has_ip) ip_samples,
                   SUM(radio_active) radio_samples,
                   MAX(COALESCE(idle, 0)) max_idle,
                   MAX(ts) last_ts
            FROM client_samples
            WHERE ts >= ?
            GROUP BY client_id
            ORDER BY client_id
            """,
            (since,),
        ).fetchall()
        event_rows = db.execute(
            """
            SELECT client_id, event, COUNT(*)
            FROM client_events
            WHERE ts >= ?
            GROUP BY client_id, event
            """,
            (since,),
        ).fetchall()
    finally:
        db.close()

    events: dict[str, dict[str, int]] = {}
    for client_id, event, count in event_rows:
        events.setdefault(client_id, {})[event] = count

    print(f"History report for last {args.since_hours:g}h")
    if not rows:
        print("No samples found.")
        return 1
    header = (
        "CLIENT".ljust(18),
        "IMSIS".ljust(24),
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
    print("-" * 118)
    for client_id, imsis, imei, samples, online, ip_samples, radio, max_idle, last_ts in rows:
        ev = events.get(client_id, {})
        up_pct = pct(online, samples)
        ip_pct = pct(ip_samples, samples)
        radio_pct = pct(radio, samples)
        last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts))
        print(
            f"{client_id:<18}  {trim(imsis or '', 24):<24}  {up_pct:>5.1f}%  {ip_pct:>5.1f}%  {radio_pct:>6.1f}%"
            f"  {ev.get('CLIENT_MISSING', 0):>6}  {ev.get('PDP_IP_LOST', 0):>7}"
            f"  {ev.get('TLLI_CHANGED', 0):>5}  {max_idle:>8}  {last_seen:<19}"
        )
    return 0


class SnifferRegisterParser:
    def __init__(self) -> None:
        self.ts = int(time.time())
        self.current: dict[str, str] = {}
        self.in_register = False

    def feed(self, lines: Iterable[str]) -> list[tuple[int, str, str]]:
        events: list[tuple[int, str, str]] = []
        for raw in lines:
            line = raw.rstrip("\r\n")
            event = self.feed_line(line)
            if event:
                events.append(event)
        return events

    def feed_line(self, line: str) -> tuple[int, str, str] | None:
        stamp = re.match(r"(\d{4}-\d{2}-\d{2})[,_ ](\d{2}:\d{2}:\d{2})", line)
        if stamp:
            try:
                self.ts = int(time.mktime(time.strptime(f"{stamp.group(1)} {stamp.group(2)}", "%Y-%m-%d %H:%M:%S")))
            except ValueError:
                self.ts = int(time.time())
        if "'user.register'" in line or "Message: user.register" in line:
            self.in_register = True
            self.current = {}
            return None
        if not self.in_register:
            return None
        param = re.search(r"param\['([^']+)'\]\s*=\s*'([^']*)'", line)
        if param:
            self.current[param.group(1)] = param.group(2)
            if self.current.get("imsi") and self.current.get("imei"):
                event = (self.ts, self.current["imsi"], self.current["imei"])
                self.current = {}
                self.in_register = False
                return event
            return None
        if line and not line.startswith((" ", "\t")):
            self.in_register = False
            self.current = {}
        return None


def parse_sniffer_registers(lines: Iterable[str]) -> list[tuple[int, str, str]]:
    return SnifferRegisterParser().feed(lines)


def import_yate_log(args: argparse.Namespace) -> int:
    if args.read_log_stdin:
        lines = sys.stdin
        source = "stdin"
    else:
        source = args.import_yate_log
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            lines = list(f)

    mappings = parse_sniffer_registers(lines)
    db = init_db(args.db)
    try:
        for ts, imsi, imei in mappings:
            update_imsi_imei_map(db, ts, imsi, imei, f"user.register:{source}")
        db.commit()
    finally:
        db.close()
    print(f"Imported {len(mappings)} IMSI↔IMEI mappings from {source} into {args.db}")
    return 0


def sniff_registers(args: argparse.Namespace) -> int:
    db = init_db(args.db)
    try:
        conn = TelnetSocket(args.host, args.port, args.timeout)
    except OSError as exc:
        db.close()
        print(f"ERROR: Yate is not reachable at {args.host}:{args.port}: {exc}", file=sys.stderr)
        print("Check: sudo systemctl status yate.service", file=sys.stderr)
        return 2

    buffer = ""
    parsed = 0
    parser = SnifferRegisterParser()
    try:
        conn.read_idle(idle_timeout=0.3, max_wait=1.5)
        for command in ("sniffer on", "sniffer filter user.register", "output on"):
            conn.write_line(command)
            conn.read_idle(idle_timeout=0.2, max_wait=0.8)
        print(f"Sniffing user.register on {args.host}:{args.port}; writing IMSI↔IMEI mappings to {args.db}")
        print("Stop with Ctrl+C.")
        while True:
            chunk = conn.read_some(timeout=1.0)
            if not chunk:
                continue
            buffer += chunk
            lines = buffer.splitlines(keepends=True)
            if lines and not lines[-1].endswith(("\n", "\r")):
                buffer = lines.pop()
            else:
                buffer = ""
            mappings = parser.feed(lines)
            for ts, imsi, imei in mappings:
                update_imsi_imei_map(db, ts, imsi, imei, "live-sniffer:user.register")
                db.commit()
                parsed += 1
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} IMSI {imsi} -> IMEI {imei}")
    except KeyboardInterrupt:
        print(f"\nStopped. Imported {parsed} mappings.")
        return 130
    except EOFError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
        conn.close()


def collect(args: argparse.Namespace) -> int:
    interval = args.watch if args.watch > 0 else 5.0
    sniffer = threading.Thread(target=sniff_registers, args=(args,), daemon=True)
    sniffer.start()
    print(f"Collecting SGSN snapshots every {interval:g}s into {args.db}")
    print("Stop with Ctrl+C.")
    try:
        while True:
            record_snapshot(args)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped collector.")
        return 130


def pct(part: int | float | None, total: int | float | None) -> float:
    if not total:
        return 0.0
    return 100.0 * float(part or 0) / float(total)



_HTML_CSS = (
    "\n:root {\n"
    "  --bg:       #07090c;\n"
    "  --surface:  #0e1317;\n"
    "  --card:     #141b22;\n"
    "  --border:   #1e2d3a;\n"
    "  --accent:   #00c8ff;\n"
    "  --ok:       #22d46e;\n"
    "  --idle:     #f5c842;\n"
    "  --noip:     #f5902e;\n"
    "  --down:     #e84040;\n"
    "  --text:     #dce8f0;\n"
    "  --muted:    #6b8090;\n"
    "  --mono:     'JetBrains Mono', 'Fira Mono', monospace;\n"
    "}\n"
    "* { box-sizing: border-box; margin: 0; padding: 0; }\n"
    "body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 28px 32px; min-height: 100vh; }\n"
    "a { color: var(--accent); text-decoration: none; }\n"
    ".page-header { display: flex; align-items: baseline; gap: 16px; margin-bottom: 28px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }\n"
    ".page-title { font-size: 20px; font-weight: 700; letter-spacing: -.3px; }\n"
    ".page-meta  { font-size: 12px; color: var(--muted); font-family: var(--mono); }\n"
    ".fleet { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }\n"
    ".fleet-stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 18px; min-width: 110px; }\n"
    ".fleet-stat .val { font-size: 28px; font-weight: 700; font-family: var(--mono); line-height: 1; }\n"
    ".fleet-stat .lbl { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .06em; }\n"
    ".val-ok { color: var(--ok); } .val-warn { color: var(--noip); } .val-crit { color: var(--down); } .val-blue { color: var(--accent); }\n"
    ".legend { display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }\n"
    ".leg-item { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); }\n"
    ".leg-dot  { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }\n"
    ".sort-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }\n"
    ".sort-bar span { font-size: 12px; color: var(--muted); margin-right: 4px; }\n"
    ".sort-btn { background: var(--card); border: 1px solid var(--border); border-radius: 5px; color: var(--muted); font-size: 12px; padding: 4px 10px; cursor: pointer; transition: border-color .15s, color .15s; }\n"
    ".sort-btn:hover, .sort-btn.active { border-color: var(--accent); color: var(--accent); }\n"
    ".client { background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; }\n"
    ".client.health-ok { border-left-color: var(--ok); } .client.health-warn { border-left-color: var(--noip); } .client.health-crit { border-left-color: var(--down); }\n"
    ".client-head { display: flex; align-items: flex-start; gap: 12px; flex-wrap: wrap; }\n"
    ".client-id { font-family: var(--mono); font-size: 14px; font-weight: 600; }\n"
    ".client-imsi { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-top: 2px; }\n"
    ".client-ip { font-size: 12px; color: var(--accent); font-family: var(--mono); font-weight: 600; flex-shrink: 0; }\n"
    ".chips { display: flex; gap: 6px; flex-wrap: wrap; margin: 10px 0; }\n"
    ".chip { font-size: 11px; font-family: var(--mono); padding: 2px 8px; border-radius: 4px; background: var(--surface); border: 1px solid var(--border); color: var(--muted); white-space: nowrap; }\n"
    ".chip .cv { color: var(--text); font-weight: 600; }\n"
    ".chip-ok { border-color: var(--ok); color: var(--ok); } .chip-warn { border-color: var(--noip); color: var(--noip); } .chip-crit { border-color: var(--down); color: var(--down); }\n"
    ".bar-group { display: flex; gap: 10px; margin: 8px 0 4px; align-items: center; flex-wrap: wrap; }\n"
    ".bar-row { display: flex; align-items: center; gap: 6px; }\n"
    ".bar-lbl { font-size: 10px; color: var(--muted); width: 42px; text-align: right; }\n"
    ".bar-track { width: 90px; height: 6px; background: var(--surface); border-radius: 3px; overflow: hidden; }\n"
    ".bar-fill { height: 100%; border-radius: 3px; }\n"
    ".bar-pct { font-size: 10px; color: var(--muted); font-family: var(--mono); width: 34px; }\n"
    ".tl-wrap { margin: 10px 0 6px; }\n"
    ".tl-label { font-size: 10px; color: var(--muted); margin-bottom: 3px; }\n"
    ".timeline { display: flex; gap: 1px; height: 18px; border-radius: 4px; overflow: hidden; }\n"
    ".seg { flex: 1; min-width: 2px; cursor: default; }\n"
    ".seg:hover { opacity: .75; }\n"
    ".seg.ok { background: var(--ok); } .seg.idle { background: var(--idle); } .seg.noip { background: var(--noip); } .seg.down { background: var(--down); }\n"
    "details { margin-top: 10px; }\n"
    "summary { font-size: 12px; color: var(--muted); cursor: pointer; user-select: none; list-style: none; display: flex; align-items: center; gap: 6px; }\n"
    "summary::before { content: '\u25b6'; font-size: 9px; transition: transform .15s; }\n"
    "details[open] summary::before { transform: rotate(90deg); }\n"
    ".evt-table { border-collapse: collapse; width: 100%; font-size: 12px; margin-top: 8px; }\n"
    ".evt-table th { background: var(--surface); color: var(--muted); text-transform: uppercase; font-size: 10px; letter-spacing: .06em; padding: 5px 8px; text-align: left; border-bottom: 1px solid var(--border); }\n"
    ".evt-table td { padding: 4px 8px; border-bottom: 1px solid var(--border); font-family: var(--mono); color: var(--text); vertical-align: top; }\n"
    ".evt-table tr:last-child td { border-bottom: none; }\n"
    ".evt-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: .04em; background: var(--surface); border: 1px solid var(--border); }\n"
    ".evt-MISSING { background: #3a1010; border-color: var(--down); color: var(--down); }\n"
    ".evt-RETURNED { background: #0d2e18; border-color: var(--ok); color: var(--ok); }\n"
    ".evt-LOST { background: #2d1e08; border-color: var(--noip); color: var(--noip); }\n"
    ".evt-RESTORED { background: #0d2533; border-color: var(--accent); color: var(--accent); }\n"
    ".evt-CHANGED { background: #2d1e08; border-color: var(--noip); color: var(--noip); }\n"
    ".empty { text-align: center; padding: 60px 20px; color: var(--muted); }\n"
)


def _evt_badge_class(event: str) -> str:
    e = event.upper()
    if "MISSING" in e or "INACTIVE" in e:
        return "evt-MISSING"
    if "RETURNED" in e or "SEEN" in e:
        return "evt-RETURNED"
    if "LOST" in e:
        return "evt-LOST"
    if "RESTORED" in e:
        return "evt-RESTORED"
    if "CHANGED" in e:
        return "evt-CHANGED"
    return ""


def _bar(pct_val: float, color: str) -> str:
    return (
        f"<div class='bar-track'>"
        f"<div class='bar-fill' style='width:{pct_val:.1f}%;background:{color}'></div>"
        f"</div>"
        f"<span class='bar-pct'>{pct_val:.0f}%</span>"
    )


def write_html_report(args: argparse.Namespace) -> int:
    db = init_db(args.db)
    since = int(time.time() - args.since_hours * 3600)
    try:
        rows = db.execute(
            "SELECT ts, client_id, imsi, online, has_ip, radio_active, ip, state, idle, tlli"
            " FROM client_samples WHERE ts >= ? ORDER BY client_id, ts",
            (since,),
        ).fetchall()
        event_rows = db.execute(
            "SELECT ts, client_id, imsi, event, old_value, new_value"
            " FROM client_events WHERE ts >= ? ORDER BY client_id, ts",
            (since,),
        ).fetchall()
    finally:
        db.close()

    by_client: dict[str, list[tuple]] = {}
    for row in rows:
        by_client.setdefault(row[1], []).append(row)
    events: dict[str, list[tuple]] = {}
    for row in event_rows:
        events.setdefault(row[1], []).append(row)

    total_clients = len(by_client)
    fleet_ok = fleet_warn = fleet_crit = 0
    fleet_avg_up = fleet_avg_ip = 0.0
    client_stats: list[dict] = []

    for client_id, samples in by_client.items():
        ev         = events.get(client_id, [])
        drops      = sum(1 for e in ev if e[3] == "CLIENT_MISSING")
        ip_lost    = sum(1 for e in ev if e[3] == "PDP_IP_LOST")
        tlli_chg   = sum(1 for e in ev if e[3] == "TLLI_CHANGED")
        sim_sw     = sum(1 for e in ev if e[3] == "SIM_SWITCHED")
        imsis      = sorted({s[2] for s in samples if s[2]})
        online_cnt = sum(1 for s in samples if s[3])
        ip_cnt     = sum(1 for s in samples if s[4])
        radio_cnt  = sum(1 for s in samples if s[5])
        n          = len(samples)
        up_pct     = pct(online_cnt, n)
        ip_pct     = pct(ip_cnt, n)
        radio_pct  = pct(radio_cnt, n)
        last       = samples[-1]
        idles      = [s[8] for s in samples if s[8] is not None]
        max_idle   = max(idles) if idles else None
        avg_idle   = sum(idles) / len(idles) if idles else None

        if drops >= 3 or up_pct < 50:
            health = "crit"; fleet_crit += 1
        elif drops >= 1 or up_pct < 90 or ip_pct < 80:
            health = "warn"; fleet_warn += 1
        else:
            health = "ok"; fleet_ok += 1

        fleet_avg_up += up_pct
        fleet_avg_ip += ip_pct
        client_stats.append(dict(
            client_id=client_id, samples=samples, ev=ev,
            drops=drops, ip_lost=ip_lost, tlli_chg=tlli_chg, sim_sw=sim_sw,
            imsis=imsis, up_pct=up_pct, ip_pct=ip_pct, radio_pct=radio_pct,
            last_ip=last[6] or "", last_state=last[7] or "", last_seen=last[0],
            health=health, max_idle=max_idle, avg_idle=avg_idle, n=n,
        ))

    if total_clients:
        fleet_avg_up /= total_clients
        fleet_avg_ip /= total_clients

    now_str = html.escape(time.strftime("%Y-%m-%d %H:%M:%S"))
    body: list[str] = []
    body.append(
        "<!doctype html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
        "<title>YateBTS \u00b7 GPRS Fleet Health</title>\n"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>\n"
        "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700"
        "&amp;family=JetBrains+Mono:wght@400;600&amp;display=swap' rel='stylesheet'>\n"
        f"<style>{_HTML_CSS}</style>\n</head>\n<body>\n"
    )
    body.append(
        f"<div class='page-header'>"
        f"<span class='page-title'>GPRS Fleet Health</span>"
        f"<span class='page-meta'>YateBTS \u00b7 generated {now_str}"
        f" \u00b7 window {args.since_hours:g}h</span></div>\n"
    )
    # fleet summary
    body.append("<div class='fleet'>")
    body.append(f"<div class='fleet-stat'><div class='val val-blue'>{total_clients}</div><div class='lbl'>Devices</div></div>")
    body.append(f"<div class='fleet-stat'><div class='val val-ok'>{fleet_ok}</div><div class='lbl'>Healthy</div></div>")
    if fleet_warn:
        body.append(f"<div class='fleet-stat'><div class='val val-warn'>{fleet_warn}</div><div class='lbl'>Warning</div></div>")
    if fleet_crit:
        body.append(f"<div class='fleet-stat'><div class='val val-crit'>{fleet_crit}</div><div class='lbl'>Critical</div></div>")
    if total_clients:
        body.append(f"<div class='fleet-stat'><div class='val' style='color:#aecde0'>{fleet_avg_up:.0f}%</div><div class='lbl'>Avg uptime</div></div>")
        body.append(f"<div class='fleet-stat'><div class='val' style='color:#aecde0'>{fleet_avg_ip:.0f}%</div><div class='lbl'>Avg IP time</div></div>")
        total_drops = sum(s["drops"] for s in client_stats)
        dc = "val-crit" if total_drops else "val-ok"
        body.append(f"<div class='fleet-stat'><div class='val {dc}'>{total_drops}</div><div class='lbl'>Total drops</div></div>")
    body.append("</div>\n")
    # legend
    body.append(
        "<div class='legend'>"
        "<span class='leg-item'><span class='leg-dot' style='background:var(--ok)'></span>Online \u00b7 IP \u00b7 radio</span>"
        "<span class='leg-item'><span class='leg-dot' style='background:var(--idle)'></span>Online \u00b7 IP \u00b7 idle</span>"
        "<span class='leg-item'><span class='leg-dot' style='background:var(--noip)'></span>Online \u00b7 no IP</span>"
        "<span class='leg-item'><span class='leg-dot' style='background:var(--down)'></span>Missing</span>"
        "</div>\n"
    )
    # sort bar
    body.append(
        "<div class='sort-bar'><span>Sort by</span>"
        "<button class='sort-btn active' onclick=\"sortCards('health')\">Health</button>"
        "<button class='sort-btn' onclick=\"sortCards('up')\">Uptime</button>"
        "<button class='sort-btn' onclick=\"sortCards('drops')\">Drops</button>"
        "<button class='sort-btn' onclick=\"sortCards('id')\">Device ID</button>"
        "</div>\n<div id='cards'>\n"
    )
    if not client_stats:
        body.append("<div class='empty'><div>No samples in the selected time window.</div></div>")

    for cs in sorted(client_stats, key=lambda x: ({"crit": 0, "warn": 1, "ok": 2}[x["health"]], -x["drops"])):
        cid       = cs["client_id"]
        h         = cs["health"]
        up_pct    = cs["up_pct"]
        ip_pct    = cs["ip_pct"]
        radio_pct = cs["radio_pct"]
        drops     = cs["drops"]
        ip_lost   = cs["ip_lost"]
        tlli_chg  = cs["tlli_chg"]
        sim_sw    = cs["sim_sw"]
        max_idle  = cs["max_idle"]
        avg_idle  = cs["avg_idle"]
        last_ip   = cs["last_ip"]
        last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cs["last_seen"]))
        imsis     = cs["imsis"]
        imsis_text = html.escape(", ".join(imsis) or "—")
        n         = cs["n"]
        h_order   = {"crit": 0, "warn": 1, "ok": 2}[h]

        body.append(
            f"<div class='client health-{h}' data-health='{h_order}'"
            f" data-up='{up_pct:.1f}' data-drops='{drops}' data-id='{html.escape(cid)}'>\n"
        )
        body.append("<div class='client-head'>")
        body.append(
            f"<div><div class='client-id'>{html.escape(cid)}</div>"
            f"<div class='client-imsi'>{imsis_text}</div></div>"
        )
        if last_ip:
            body.append(f"<div class='client-ip'>{html.escape(last_ip)}</div>")
        body.append(
            f"<div style='margin-left:auto;font-size:11px;color:var(--muted)'>"
            f"last seen {html.escape(last_seen)}</div></div>\n"
        )
        # chips
        chip_drops_cls = "chip-crit" if drops >= 3 else ("chip-warn" if drops >= 1 else "")
        chip_idle_cls  = "chip-warn" if (max_idle is not None and max_idle >= 300) else ""
        chip_ip_cls    = "chip-warn" if ip_lost else ""
        body.append("<div class='chips'>")
        body.append(f"<span class='chip {chip_drops_cls}'>drops <span class='cv'>{drops}</span></span>")
        body.append(f"<span class='chip {chip_ip_cls}'>ip_lost <span class='cv'>{ip_lost}</span></span>")
        if tlli_chg:
            body.append(f"<span class='chip'>tlli_chg <span class='cv'>{tlli_chg}</span></span>")
        if sim_sw:
            body.append(f"<span class='chip chip-warn'>sim_switch <span class='cv'>{sim_sw}</span></span>")
        if max_idle is not None:
            body.append(f"<span class='chip {chip_idle_cls}'>max_idle <span class='cv'>{max_idle}s</span></span>")
        if avg_idle is not None:
            body.append(f"<span class='chip'>avg_idle <span class='cv'>{avg_idle:.0f}s</span></span>")
        body.append(f"<span class='chip'>samples <span class='cv'>{n}</span></span>")
        body.append("</div>\n")
        # bars
        body.append("<div class='bar-group'>")
        body.append(f"<div class='bar-row'><span class='bar-lbl'>uptime</span>{_bar(up_pct,'var(--ok)')}</div>")
        body.append(f"<div class='bar-row'><span class='bar-lbl'>ip</span>{_bar(ip_pct,'var(--accent)')}</div>")
        body.append(f"<div class='bar-row'><span class='bar-lbl'>radio</span>{_bar(radio_pct,'var(--idle)')}</div>")
        body.append("</div>\n")
        # timeline
        body.append("<div class='tl-wrap'><div class='tl-label'>Timeline</div><div class='timeline'>")
        for ts_s, _, imsi_s, online_v, has_ip_v, radio_v, ip_v, state_v, idle_v, tlli_v in cs["samples"]:
            if not online_v:
                cls = "down"
            elif not has_ip_v:
                cls = "noip"
            elif not radio_v:
                cls = "idle"
            else:
                cls = "ok"
            t_str = time.strftime("%H:%M:%S", time.localtime(ts_s))
            title = (
                f"{t_str} imsi={imsi_s or '-'} ip={ip_v or '-'}"
                f" state={state_v or '-'} idle={idle_v if idle_v is not None else '-'} tlli={tlli_v or '-'}"
            )
            body.append(f"<span class='seg {cls}' title='{html.escape(title)}'></span>")
        body.append("</div></div>\n")
        # events
        ev = cs["ev"]
        if ev:
            body.append(f"<details><summary>{len(ev)} events (last 30)</summary>")
            body.append(
                "<table class='evt-table'>"
                "<tr><th>Time</th><th>Event</th><th>IMSI</th><th>Old</th><th>New</th></tr>"
            )
            for ts_e, _, imsi_e, event_e, old_e, new_e in ev[-30:]:
                t_str = html.escape(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_e)))
                badge_cls = _evt_badge_class(event_e)
                body.append(
                    f"<tr><td>{t_str}</td>"
                    f"<td><span class='evt-badge {badge_cls}'>{html.escape(event_e)}</span></td>"
                    f"<td>{html.escape(imsi_e or '')}</td>"
                    f"<td style='color:var(--muted)'>{html.escape(old_e or '')}</td>"
                    f"<td>{html.escape(new_e or '')}</td></tr>"
                )
            body.append("</table></details>\n")
        body.append("</div>\n")

    body.append("</div>\n")  # #cards
    body.append(
        "<script>\n"
        "function sortCards(by){\n"
        "  document.querySelectorAll('.sort-btn').forEach(function(b){b.classList.remove('active');});\n"
        "  event.target.classList.add('active');\n"
        "  var wrap=document.getElementById('cards');\n"
        "  var cards=Array.prototype.slice.call(wrap.querySelectorAll('.client'));\n"
        "  cards.sort(function(a,b){\n"
        "    if(by==='health') return +a.dataset.health - +b.dataset.health;\n"
        "    if(by==='up') return +a.dataset.up - +b.dataset.up;\n"
        "    if(by==='drops') return +b.dataset.drops - +a.dataset.drops;\n"
        "    if(by==='id') return a.dataset.id<b.dataset.id?-1:1;\n"
        "    return 0;\n"
        "  });\n"
        "  cards.forEach(function(c){wrap.appendChild(c);});\n"
        "}\n"
        "</script>\n</body></html>"
    )

    with open(args.html_report, "w", encoding="utf-8") as f:
        f.write("\n".join(body))
    print(f"Wrote {args.html_report}")
    return 0

def once(args: argparse.Namespace) -> int:
    if args.collect:
        return collect(args)
    if args.sniff_registers:
        return sniff_registers(args)
    if args.import_yate_log or args.read_log_stdin:
        return import_yate_log(args)
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
    parser.add_argument("--import-yate-log", default="", help="Import Yate sniffer user.register log and map IMSI to IMEI")
    parser.add_argument("--read-log-stdin", action="store_true", help="Read Yate sniffer user.register log from stdin")
    parser.add_argument("--sniff-registers", action="store_true", help="Continuously read telnet sniffer user.register and map IMSI to IMEI")
    parser.add_argument("--collect", action="store_true", help="Run live IMEI sniffer and periodic SGSN recorder in one process")
    args = parser.parse_args()

    if args.collect:
        return collect(args)

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
