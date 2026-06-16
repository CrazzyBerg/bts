#!/usr/bin/env python3
"""
Local web UI for a small YateBTS Raspberry Pi cluster.

The server intentionally uses only the Python standard library so it can run on
a controller machine without installing npm or pip dependencies.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import html
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("BTS_CLUSTER_DATA", PROJECT_ROOT / ".bts_cluster_web"))
INVENTORY_PATH = DATA_DIR / "inventory.json"

DEFAULT_USER = "pi"
DEFAULT_PASSWORD = "raspberry"
DEFAULT_SSH_PORT = 22
DEFAULT_TELNET_PORT = 5038
DEFAULT_SERVICE = "yate.service"
RMANAGER_CONF_PATH = "/usr/local/etc/yate/rmanager.conf"
RMANAGER_BIND_ADDR = "0.0.0.0"
YBTS_CONF_PATH = "/usr/local/etc/yate/ybts.conf"
MAX_SCAN_HOSTS = 1024

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
YBTS_CONFIG_RE = re.compile(
    r"^\s*;?\s*(Radio\.Band|Radio\.C0|MS\.IP\.Base|MS\.IP\.MaxCount)\s*=\s*([^;#\r\n]*)"
)

TELNET_TEMPLATES = [
    {"name": "SGSN clients", "command": "mbts sgsn list"},
    {"name": "GPRS status", "command": "mbts gprs stat"},
    {"name": "BTS load", "command": "mbts load"},
    {"name": "TBF list", "command": "mbts gprs list tbf"},
    {"name": "PDCH list", "command": "mbts gprs list ch"},
    {"name": "Version", "command": "version"},
    {"name": "Help", "command": "help"},
]


@dataclass
class Node:
    id: str
    name: str
    ip: str
    user: str = DEFAULT_USER
    password: str = DEFAULT_PASSWORD
    ssh_port: int = DEFAULT_SSH_PORT
    telnet_port: int = DEFAULT_TELNET_PORT
    service: str = DEFAULT_SERVICE
    radio_band: str = ""
    radio_c0: str = ""
    ms_ip_base: str = ""
    ms_ip_max_count: str = ""
    created_at: int = 0
    updated_at: int = 0


def now_ts() -> int:
    return int(time.time())


def load_nodes() -> list[Node]:
    if not INVENTORY_PATH.exists():
        return []
    try:
        raw = json.loads(INVENTORY_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    nodes: list[Node] = []
    for item in raw.get("nodes", []):
        try:
            nodes.append(Node(**item))
        except TypeError:
            continue
    return nodes


def save_nodes(nodes: list[Node]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"nodes": [asdict(node) for node in nodes]}
    INVENTORY_PATH.write_text(json.dumps(payload, indent=2) + "\n")
    try:
        INVENTORY_PATH.chmod(0o600)
    except OSError:
        pass


def find_node(nodes: list[Node], node_id: str) -> Node | None:
    for node in nodes:
        if node.id == node_id:
            return node
    return None


def validate_ip(value: str) -> str:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def normalize_radio_band(value: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", value):
        raise ValueError("Invalid Radio.Band value")
    return value


def normalize_radio_c0(value: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        arfcn = int(value)
    except ValueError as exc:
        raise ValueError("Radio.C0 must be a number") from exc
    if arfcn < 0 or arfcn > 1023:
        raise ValueError("Radio.C0 must be between 0 and 1023")
    return str(arfcn)


def normalize_ms_ip_base(value: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("MS.IP.Base must be a valid IP address") from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("MS.IP.Base must be an IPv4 address")
    return str(ip)


def normalize_ms_ip_max_count(value: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        count = int(value)
    except ValueError as exc:
        raise ValueError("MS.IP.MaxCount must be a number") from exc
    if count < 1 or count > 65535:
        raise ValueError("MS.IP.MaxCount must be between 1 and 65535")
    return str(count)


def frequency_key(node: Node) -> tuple[str, str] | None:
    if not node.radio_band or not node.radio_c0:
        return None
    return (node.radio_band.lower(), node.radio_c0)


def ms_ip_range(node: Node) -> tuple[int, int] | None:
    if not node.ms_ip_base or not node.ms_ip_max_count:
        return None
    start = int(ipaddress.IPv4Address(node.ms_ip_base))
    count = int(node.ms_ip_max_count)
    end = start + count - 1
    if end > int(ipaddress.IPv4Address("255.255.255.255")):
        raise ValueError("MS.IP range exceeds IPv4 address space")
    return (start, end)


def ip_ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] <= right[1] and right[0] <= left[1]


def parse_ybts_config_text(text: str) -> dict[str, str]:
    parsed = {
        "radio_band": "",
        "radio_c0": "",
        "ms_ip_base": "",
        "ms_ip_max_count": "",
    }
    key_map = {
        "Radio.Band": "radio_band",
        "Radio.C0": "radio_c0",
        "MS.IP.Base": "ms_ip_base",
        "MS.IP.MaxCount": "ms_ip_max_count",
    }
    for line in text.splitlines():
        match = YBTS_CONFIG_RE.match(line)
        if not match:
            continue
        key, value = match.groups()
        parsed[key_map[key]] = value.strip()
    return parsed


def validate_node_uniqueness(nodes: list[Node], candidate: Node) -> None:
    candidate_ms_range = ms_ip_range(candidate)
    for node in nodes:
        if node.id == candidate.id:
            continue
        if node.ip == candidate.ip:
            raise ValueError(f"IP address {candidate.ip} is already assigned to {node.name or node.id}")
        if frequency_key(node) and frequency_key(node) == frequency_key(candidate):
            raise ValueError(
                f"Radio.Band {candidate.radio_band} with Radio.C0 {candidate.radio_c0} "
                f"is already assigned to {node.name or node.ip}"
            )
        node_ms_range = ms_ip_range(node)
        if candidate_ms_range and node_ms_range and ip_ranges_overlap(candidate_ms_range, node_ms_range):
            raise ValueError(
                f"MS IP range {candidate.ms_ip_base}/{candidate.ms_ip_max_count} "
                f"overlaps with {node.name or node.ip}"
            )


def inventory_conflicts(nodes: list[Node]) -> dict[str, list[str]]:
    conflicts: dict[str, list[str]] = {node.id: [] for node in nodes}
    for idx, left in enumerate(nodes):
        for right in nodes[idx + 1 :]:
            if left.ip == right.ip:
                message = f"Duplicate IP {left.ip}"
                conflicts[left.id].append(message)
                conflicts[right.id].append(message)
            if frequency_key(left) and frequency_key(left) == frequency_key(right):
                message = f"Duplicate Radio.Band {left.radio_band} / Radio.C0 {left.radio_c0}"
                conflicts[left.id].append(message)
                conflicts[right.id].append(message)
            left_ms_range = ms_ip_range(left)
            right_ms_range = ms_ip_range(right)
            if left_ms_range and right_ms_range and ip_ranges_overlap(left_ms_range, right_ms_range):
                message = "Overlapping MS.IP range"
                conflicts[left.id].append(message)
                conflicts[right.id].append(message)
    return conflicts


def node_with_live_config(node: Node, live: dict[str, Any] | None) -> Node:
    data = asdict(node)
    if live:
        for field in ("radio_band", "radio_c0", "ms_ip_base", "ms_ip_max_count"):
            if not data.get(field) and live.get(field):
                data[field] = str(live[field])
    return Node(**data)


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    body = handler.rfile.read(length)
    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Request body must be JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Request body must be a JSON object")
    return parsed


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def text_response(handler: BaseHTTPRequestHandler, status: int, text: str, content_type: str = "text/html") -> None:
    data = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def error_response(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    json_response(handler, status, {"ok": False, "error": message})


def has_sshpass() -> bool:
    return shutil.which("sshpass") is not None


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "192.168.1.1"
    finally:
        sock.close()


def default_cidr() -> str:
    ip = ipaddress.ip_address(local_ipv4())
    if not isinstance(ip, ipaddress.IPv4Address):
        return "192.168.1.0/24"
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def strip_telnet_iac(data: bytes) -> bytes:
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


class TelnetSession:
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


def run_telnet(ip: str, port: int, command: str, timeout: float = 6.0) -> dict[str, Any]:
    command = command.strip()
    if not command:
        raise ValueError("Telnet command is empty")
    if len(command) > 300:
        raise ValueError("Telnet command is too long")
    session = TelnetSession(ip, port, timeout)
    try:
        session.read_idle(0.25, 1.0)
        session.write_line(command)
        output = session.read_idle(0.5, timeout)
        session.write_line("quit")
        return {"ok": True, "output": output}
    finally:
        session.close()


def ssh_command(node: Node, remote_command: str, timeout: int = 8, batch: bool = False) -> tuple[list[str], dict[str, str]]:
    env = os.environ.copy()
    command = [
        "ssh",
        "-p",
        str(node.ssh_port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"ConnectTimeout={max(1, min(timeout, 10))}",
        "-o",
        f"BatchMode={'yes' if batch else 'no'}",
        f"{node.user}@{node.ip}",
        remote_command,
    ]
    if node.password:
        if not has_sshpass():
            raise RuntimeError("sshpass is not installed")
        env["SSHPASS"] = node.password
        command = ["sshpass", "-e", *command]
    return command, env


def run_ssh(node: Node, remote_command: str, timeout: int = 12, batch: bool = False) -> dict[str, Any]:
    command, env = ssh_command(node, remote_command, timeout=timeout, batch=batch)
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 124, "stdout": "", "stderr": "SSH command timed out"}
    except OSError as exc:
        return {"ok": False, "rc": 127, "stdout": "", "stderr": str(exc)}
    return {
        "ok": result.returncode == 0,
        "rc": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def sudo_shell_command(node: Node, command: str) -> str:
    if node.password:
        return f"printf '%s\\n' {shlex.quote(node.password)} | sudo -S -p '' sh -c {shlex.quote(command)}"
    return f"sudo -n sh -c {shlex.quote(command)}"


def run_service_action(node: Node, action: str) -> dict[str, Any]:
    if action not in {"start", "restart", "stop"}:
        raise ValueError("Unsupported service action")
    if not SERVICE_RE.match(node.service):
        raise ValueError("Invalid service name")
    service = node.service
    remote = sudo_shell_command(node, f"systemctl {action} {service}")
    return run_ssh(node, remote, timeout=25)


def rmanager_addr_update_script() -> str:
    return r"""
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
addr = sys.argv[2]
section_re = re.compile(r"^\s*\[([^]]+)]")
addr_re = re.compile(r"^\s*;?\s*addr\s*=")

lines = path.read_text().splitlines() if path.exists() else []
general_start = None
general_end = len(lines)

for idx, line in enumerate(lines):
    match = section_re.match(line)
    if not match:
        continue
    if general_start is not None:
        general_end = idx
        break
    if match.group(1).strip().lower() == "general":
        general_start = idx

if general_start is None:
    lines = ["[general]", f"addr={addr}", "", *lines]
else:
    changed = False
    for idx in range(general_start + 1, general_end):
        if addr_re.match(lines[idx]):
            lines[idx] = f"addr={addr}"
            changed = True
            break
    if not changed:
        lines.insert(general_start + 1, f"addr={addr}")

path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(lines).rstrip() + "\n")
""".strip()


def run_configure_rmanager_addr(node: Node) -> dict[str, Any]:
    if not SERVICE_RE.match(node.service):
        raise ValueError("Invalid service name")
    script = rmanager_addr_update_script()
    python_command = " ".join(
        [
            "python3",
            "-c",
            shlex.quote(script),
            shlex.quote(RMANAGER_CONF_PATH),
            shlex.quote(RMANAGER_BIND_ADDR),
        ]
    )
    remote = sudo_shell_command(node, f"{python_command} && systemctl restart {node.service}")
    return run_ssh(node, remote, timeout=30)


def validate_log_path(value: str) -> str:
    path = value.strip() or "/var/log/yate.err"
    if not path.startswith("/"):
        raise ValueError("Log path must be absolute")
    if "\x00" in path or "\n" in path or "\r" in path or len(path) > 200:
        raise ValueError("Invalid log path")
    return path


def normalize_tail_lines(value: str) -> int:
    try:
        lines = int(value)
    except (TypeError, ValueError):
        return 200
    return max(0, min(lines, 2000))


def build_tail_command(node: Node, path: str, lines: int, use_sudo: bool) -> str:
    tail = f"tail -n {lines} -F -- {shlex.quote(path)}"
    if not use_sudo:
        return tail
    if node.password:
        return f"printf '%s\\n' {shlex.quote(node.password)} | sudo -S -p '' {tail}"
    return f"sudo -n {tail}"


def parse_service_status_stdout(stdout: str) -> dict[str, str]:
    values = {
        "hostname": "",
        "service": "unknown",
        "active_state": "",
        "substate": "",
        "main_pid": "",
        "yate_pid": "",
        "yate_cmd_pid": "",
    }
    ybts = parse_ybts_config_text(stdout)
    for line in stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in values:
            values[key] = value.strip()

    service = values["service"] or values["active_state"] or "unknown"
    process_alive = values["main_pid"].isdigit() and int(values["main_pid"]) > 0
    process_alive = process_alive or bool(values["yate_pid"] or values["yate_cmd_pid"])
    if service != "active" and process_alive:
        service = "active"
    elif service == "unknown" and values["substate"] == "running":
        service = "active"

    return {
        "hostname": values["hostname"],
        "service": service,
        "active_state": values["active_state"],
        "substate": values["substate"],
        "main_pid": values["main_pid"],
        "yate_pid": values["yate_pid"],
        "yate_cmd_pid": values["yate_cmd_pid"],
        **ybts,
    }


def service_status(node: Node) -> dict[str, Any]:
    service = shlex.quote(node.service)
    ybts_conf = shlex.quote(YBTS_CONF_PATH)
    command = (
        "printf 'hostname='; hostname 2>/dev/null || true; printf '\\n'; "
        "printf 'yate_pid='; pgrep -x yate 2>/dev/null | head -n 1 || true; printf '\\n'; "
        "printf 'yate_cmd_pid='; pgrep -f '(^|/)(lt-)?yate([[:space:]]|$)|/usr/local/bin/yate' 2>/dev/null | head -n 1 || true; printf '\\n'; "
        f"printf 'service='; systemctl is-active {service} 2>/dev/null || true; printf '\\n'; "
        f"printf 'active_state='; systemctl show -p ActiveState --value {service} 2>/dev/null || true; printf '\\n'; "
        f"printf 'substate='; systemctl show -p SubState --value {service} 2>/dev/null || true; printf '\\n'; "
        f"printf 'main_pid='; systemctl show -p MainPID --value {service} 2>/dev/null || true; printf '\\n'; "
        f"sed -n '/^[[:space:]]*;\\?[[:space:]]*\\(Radio\\.Band\\|Radio\\.C0\\|MS\\.IP\\.Base\\|MS\\.IP\\.MaxCount\\)[[:space:]]*=/p' {ybts_conf} 2>/dev/null || true"
    )
    result = run_ssh(node, command, timeout=10, batch=not bool(node.password))
    parsed = parse_service_status_stdout(result["stdout"])
    parsed["ssh"] = result
    return parsed


def probe_node(node: Node, verify_auth: bool = True, timeout: float = 1.2) -> dict[str, Any]:
    ssh_open = tcp_open(node.ip, node.ssh_port, timeout)
    telnet_open = tcp_open(node.ip, node.telnet_port, timeout)
    info: dict[str, Any] = {
        "ip": node.ip,
        "ssh_open": ssh_open,
        "telnet_open": telnet_open,
        "online": ssh_open or telnet_open,
        "auth_ok": None,
        "hostname": "",
        "service": "unknown",
        "checked_at": now_ts(),
    }
    if verify_auth and ssh_open:
        try:
            status = service_status(node)
            info["auth_ok"] = bool(status["ssh"]["ok"])
            info["hostname"] = status["hostname"]
            info["service"] = status["service"]
            info["radio_band"] = status.get("radio_band", "")
            info["radio_c0"] = status.get("radio_c0", "")
            info["ms_ip_base"] = status.get("ms_ip_base", "")
            info["ms_ip_max_count"] = status.get("ms_ip_max_count", "")
            if info["service"] == "unknown" and telnet_open:
                info["service"] = "active"
            if not status["ssh"]["ok"]:
                info["auth_error"] = compact_error(status["ssh"]["stderr"])
        except RuntimeError as exc:
            info["auth_ok"] = None
            info["auth_error"] = str(exc)
    elif telnet_open:
        info["service"] = "active"
    return info


def compact_error(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1][:240]


def telnet_error_message(exc: OSError, ip: str, port: int) -> str:
    endpoint = f"{ip}:{port}"
    if isinstance(exc, socket.timeout) or exc.errno == errno.ETIMEDOUT:
        return f"Telnet connection to {endpoint} timed out. Check network reachability and firewall rules."
    if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
        return (
            f"Telnet connection refused by {endpoint}. "
            "Yate rmanager is not listening there. Check yate.service, rmanager.conf, and the node telnet port."
        )
    if exc.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN, errno.ENETDOWN}:
        return f"Telnet endpoint {endpoint} is unreachable. Check the node IP address and network route."
    return f"Telnet connection to {endpoint} failed: {exc}"


def scan_host(ip: str, user: str, password: str, ssh_port: int, telnet_port: int, timeout: float) -> dict[str, Any] | None:
    ssh_open = tcp_open(ip, ssh_port, timeout)
    telnet_open = tcp_open(ip, telnet_port, timeout)
    if not (ssh_open or telnet_open):
        return None
    node = Node(
        id="scan",
        name=f"bts-{ip}",
        ip=ip,
        user=user,
        password=password,
        ssh_port=ssh_port,
        telnet_port=telnet_port,
        service=DEFAULT_SERVICE,
    )
    info = probe_node(node, verify_auth=ssh_open, timeout=timeout)
    return info


def scan_subnet(
    cidr: str,
    user: str = DEFAULT_USER,
    password: str = DEFAULT_PASSWORD,
    ssh_port: int = DEFAULT_SSH_PORT,
    telnet_port: int = DEFAULT_TELNET_PORT,
    timeout: float = 1.0,
) -> list[dict[str, Any]]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {cidr}") from exc
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > MAX_SCAN_HOSTS:
        raise ValueError(f"Subnet is too large: {len(hosts)} hosts, max {MAX_SCAN_HOSTS}")
    results: list[dict[str, Any]] = []
    workers = min(64, max(4, len(hosts)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_host, ip, user, password, ssh_port, telnet_port, timeout)
            for ip in hosts
        ]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                results.append(item)
    results.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))
    return results


def node_public(
    node: Node,
    live: dict[str, Any] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, Any]:
    data = asdict(node)
    data.pop("password", None)
    data["has_password"] = bool(node.password)
    data["conflicts"] = conflicts or []
    if live:
        data["live"] = live
    return data


def upsert_discovered(discoveries: list[dict[str, Any]], user: str, password: str) -> list[Node]:
    nodes = load_nodes()
    by_ip = {node.ip: node for node in nodes}
    ts = now_ts()
    for item in discoveries:
        if not item.get("auth_ok"):
            continue
        ip = item["ip"]
        node = by_ip.get(ip)
        if node is None:
            node = Node(
                id=str(uuid.uuid4()),
                name=item.get("hostname") or f"bts-{ip}",
                ip=ip,
                user=user,
                password=password,
                radio_band=str(item.get("radio_band") or ""),
                radio_c0=str(item.get("radio_c0") or ""),
                ms_ip_base=str(item.get("ms_ip_base") or ""),
                ms_ip_max_count=str(item.get("ms_ip_max_count") or ""),
                created_at=ts,
                updated_at=ts,
            )
            nodes.append(node)
            by_ip[ip] = node
        else:
            node.user = user
            node.password = password
            node.updated_at = ts
            if item.get("hostname"):
                node.name = item["hostname"]
            for field in ("radio_band", "radio_c0", "ms_ip_base", "ms_ip_max_count"):
                if not getattr(node, field) and item.get(field):
                    setattr(node, field, str(item[field]))
    save_nodes(nodes)
    return nodes


class App(BaseHTTPRequestHandler):
    server_version = "BTSClusterWeb/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            text_response(self, HTTPStatus.OK, INDEX_HTML)
            return
        match = re.match(r"^/api/nodes/([^/]+)/logs/stream$", parsed.path)
        if match:
            self.stream_logs(match.group(1), parse_qs(parsed.query))
            return
        if parsed.path == "/api/config":
            json_response(
                self,
                HTTPStatus.OK,
                {
                    "ok": True,
                    "default_cidr": default_cidr(),
                    "sshpass": has_sshpass(),
                    "templates": TELNET_TEMPLATES,
                    "inventory_path": str(INVENTORY_PATH),
                },
            )
            return
        if parsed.path == "/api/nodes":
            query = parse_qs(parsed.query)
            want_live = query.get("live", ["1"])[0] != "0"
            nodes = load_nodes()
            live_by_id: dict[str, dict[str, Any]] = {}
            if want_live and nodes:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as executor:
                    futures = {executor.submit(probe_node, node, True): node.id for node in nodes}
                    for future in concurrent.futures.as_completed(futures):
                        live_by_id[futures[future]] = future.result()
            conflict_nodes = [node_with_live_config(node, live_by_id.get(node.id)) for node in nodes]
            conflicts_by_id = inventory_conflicts(conflict_nodes)
            json_response(
                self,
                HTTPStatus.OK,
                {
                    "ok": True,
                    "nodes": [
                        node_public(node, live_by_id.get(node.id), conflicts_by_id.get(node.id))
                        for node in nodes
                    ],
                },
            )
            return
        error_response(self, HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = read_json(self)
            if parsed.path == "/api/nodes":
                self.create_node(payload)
                return
            if parsed.path == "/api/scan":
                self.scan(payload)
                return
            match = re.match(r"^/api/nodes/([^/]+)/(action|telnet)$", parsed.path)
            if match:
                node_id, operation = match.groups()
                if operation == "action":
                    self.node_action(node_id, payload)
                else:
                    self.node_telnet(node_id, payload)
                return
        except ValueError as exc:
            error_response(self, HTTPStatus.BAD_REQUEST, str(exc))
            return
        except RuntimeError as exc:
            error_response(self, HTTPStatus.FAILED_DEPENDENCY, str(exc))
            return
        error_response(self, HTTPStatus.NOT_FOUND, "Not found")

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        match = re.match(r"^/api/nodes/([^/]+)$", parsed.path)
        if not match:
            error_response(self, HTTPStatus.NOT_FOUND, "Not found")
            return
        node_id = match.group(1)
        nodes = load_nodes()
        kept = [node for node in nodes if node.id != node_id]
        if len(kept) == len(nodes):
            error_response(self, HTTPStatus.NOT_FOUND, "Unknown node")
            return
        save_nodes(kept)
        json_response(self, HTTPStatus.OK, {"ok": True})

    def create_node(self, payload: dict[str, Any]) -> None:
        ip = validate_ip(str(payload.get("ip", "")))
        ts = now_ts()
        nodes = load_nodes()
        existing = next((node for node in nodes if node.ip == ip), None)
        node = existing or Node(id=str(uuid.uuid4()), name="", ip=ip, created_at=ts)
        node.name = str(payload.get("name") or node.name or f"bts-{ip}").strip()
        node.user = str(payload.get("user") or DEFAULT_USER).strip()
        node.password = str(payload.get("password") if payload.get("password") is not None else DEFAULT_PASSWORD)
        node.ssh_port = int(payload.get("ssh_port") or DEFAULT_SSH_PORT)
        node.telnet_port = int(payload.get("telnet_port") or DEFAULT_TELNET_PORT)
        node.service = str(payload.get("service") or DEFAULT_SERVICE).strip()
        node.radio_band = normalize_radio_band(payload.get("radio_band"))
        node.radio_c0 = normalize_radio_c0(payload.get("radio_c0"))
        node.ms_ip_base = normalize_ms_ip_base(payload.get("ms_ip_base"))
        node.ms_ip_max_count = normalize_ms_ip_max_count(payload.get("ms_ip_max_count"))
        if not SERVICE_RE.match(node.service):
            raise ValueError("Invalid service name")
        validate_node_uniqueness(nodes, node)
        node.updated_at = ts
        if existing is None:
            nodes.append(node)
        save_nodes(nodes)
        live = probe_node(node, verify_auth=True)
        json_response(self, HTTPStatus.OK, {"ok": True, "node": node_public(node, live)})

    def scan(self, payload: dict[str, Any]) -> None:
        cidr = str(payload.get("cidr") or default_cidr()).strip()
        user = str(payload.get("user") or DEFAULT_USER).strip()
        password = str(payload.get("password") if payload.get("password") is not None else DEFAULT_PASSWORD)
        ssh_port = int(payload.get("ssh_port") or DEFAULT_SSH_PORT)
        telnet_port = int(payload.get("telnet_port") or DEFAULT_TELNET_PORT)
        auto_add = bool(payload.get("auto_add", True))
        discoveries = scan_subnet(cidr, user, password, ssh_port, telnet_port, timeout=1.0)
        if auto_add:
            upsert_discovered(discoveries, user, password)
        json_response(self, HTTPStatus.OK, {"ok": True, "discoveries": discoveries})

    def node_action(self, node_id: str, payload: dict[str, Any]) -> None:
        nodes = load_nodes()
        node = find_node(nodes, node_id)
        if node is None:
            error_response(self, HTTPStatus.NOT_FOUND, "Unknown node")
            return
        action = str(payload.get("action") or "")
        if action == "configure-rmanager-addr":
            result = run_configure_rmanager_addr(node)
        else:
            result = run_service_action(node, action)
        live = probe_node(node, verify_auth=True)
        json_response(self, HTTPStatus.OK, {"ok": result["ok"], "result": result, "live": live})

    def node_telnet(self, node_id: str, payload: dict[str, Any]) -> None:
        nodes = load_nodes()
        node = find_node(nodes, node_id)
        if node is None:
            error_response(self, HTTPStatus.NOT_FOUND, "Unknown node")
            return
        command = str(payload.get("command") or "")
        try:
            result = run_telnet(node.ip, node.telnet_port, command)
        except OSError as exc:
            json_response(
                self,
                HTTPStatus.OK,
                {"ok": False, "output": "", "error": telnet_error_message(exc, node.ip, node.telnet_port)},
            )
            return
        json_response(self, HTTPStatus.OK, result)

    def send_sse(self, event: str, payload: dict[str, Any]) -> None:
        self.wfile.write(f"event: {event}\n".encode("utf-8"))
        data = json.dumps(payload, ensure_ascii=False)
        for line in data.splitlines() or [""]:
            self.wfile.write(f"data: {line}\n".encode("utf-8"))
        self.wfile.write(b"\n")
        self.wfile.flush()

    def stream_logs(self, node_id: str, query: dict[str, list[str]]) -> None:
        nodes = load_nodes()
        node = find_node(nodes, node_id)
        if node is None:
            error_response(self, HTTPStatus.NOT_FOUND, "Unknown node")
            return
        try:
            path = validate_log_path(query.get("path", ["/var/log/yate.err"])[0])
            lines = normalize_tail_lines(query.get("lines", ["200"])[0])
            use_sudo = query.get("sudo", ["0"])[0] in {"1", "true", "yes"}
            remote = build_tail_command(node, path, lines, use_sudo)
            command, env = ssh_command(node, remote, timeout=10, batch=not bool(node.password))
        except (ValueError, RuntimeError) as exc:
            error_response(self, HTTPStatus.BAD_REQUEST, str(exc))
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                bufsize=1,
            )
            self.send_sse("status", {"message": f"tail -F {path}", "ip": node.ip})
            assert proc.stdout is not None
            for line in proc.stdout:
                self.send_sse("line", {"text": line.rstrip("\n")})
            rc = proc.wait(timeout=2)
            self.send_sse("exit", {"rc": rc})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except OSError as exc:
            try:
                self.send_sse("logerror", {"message": str(exc)})
            except OSError:
                pass
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BTS Cluster</title>
  <style>
    :root {
      color-scheme: light;
      --font-sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --bg: #eef1f4;
      --surface: #f7f8fa;
      --panel: #ffffff;
      --panel-alt: #f3f5f7;
      --text: #1b2128;
      --muted: #66717f;
      --subtle: #98a2af;
      --line: #dce2e8;
      --line-strong: #c6ced7;
      --info-bg: #e9f1ff;
      --info-text: #1e5bb8;
      --info-line: #b9d0fb;
      --ok-bg: #e8f7ef;
      --ok-text: #0f6842;
      --ok-line: #bce5cf;
      --warn-bg: #fff4df;
      --warn-text: #875400;
      --warn-line: #edcf95;
      --bad-bg: #fdecec;
      --bad-text: #9e2222;
      --bad-line: #efb9b9;
      --terminal-bg: #0d1117;
      --terminal-panel: #161b22;
      --terminal-line: #30363d;
      --terminal-text: #e6edf3;
      --terminal-muted: #8b949e;
      --terminal-blue: #58a6ff;
      --shadow: 0 1px 3px rgba(20, 30, 44, .07);
      --radius: 6px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14px;
      letter-spacing: 0;
    }
    button, input {
      font: inherit;
    }
    button {
      border: .5px solid var(--line-strong);
      background: var(--panel);
      color: var(--text);
      border-radius: var(--radius);
      min-height: 32px;
      padding: 6px 11px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
    }
    button.primary {
      background: var(--info-bg);
      color: var(--info-text);
      border-color: var(--info-line);
    }
    button.danger {
      background: var(--bad-bg);
      color: var(--bad-text);
      border-color: var(--bad-line);
    }
    button:disabled {
      opacity: .55;
      cursor: not-allowed;
    }
    input {
      width: 100%;
      min-height: 32px;
      border: .5px solid var(--line);
      border-radius: 4px;
      background: var(--panel-alt);
      color: var(--text);
      padding: 6px 9px;
      font-size: 12px;
    }
    input[type="checkbox"] {
      width: auto;
      min-height: 0;
    }
    label {
      display: grid;
      gap: 5px;
      color: var(--muted);
      font-size: 11px;
      font-weight: 600;
    }
    .bts-root {
      min-height: 100vh;
      background: var(--surface);
    }
    .bts-header {
      min-height: 58px;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      background: var(--panel);
      border-bottom: .5px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    .bts-logo {
      display: flex;
      align-items: center;
      gap: 9px;
    }
    .bts-signal-icon {
      width: 30px;
      height: 30px;
      border-radius: var(--radius);
      background: var(--info-bg);
      border: .5px solid var(--info-line);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--info-text);
      font-family: var(--font-mono);
      font-size: 15px;
      font-weight: 600;
    }
    .bts-logo-text {
      font-size: 14px;
      font-weight: 700;
      line-height: 1.15;
    }
    .bts-logo-sub {
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: .5px;
      margin-top: 2px;
    }
    .bts-header-right {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .bts-subnet-pill {
      color: var(--muted);
      background: var(--panel-alt);
      border: .5px solid var(--line);
      border-radius: 20px;
      padding: 4px 10px;
      font-family: var(--font-mono);
      font-size: 11px;
    }
    .bts-header .app-tab.active {
      background: var(--info-bg);
      color: var(--info-text);
      border-color: var(--info-line);
    }
    .bts-body {
      display: grid;
      grid-template-columns: 224px minmax(0, 1fr);
      min-height: calc(100vh - 58px);
    }
    .bts-sidebar {
      background: var(--panel);
      border-right: .5px solid var(--line);
      padding: 16px 0;
    }
    .bts-sidebar-section {
      padding: 0 14px;
      margin-bottom: 18px;
    }
    .bts-sidebar-label {
      color: var(--subtle);
      font-size: 10px;
      font-weight: 700;
      letter-spacing: .8px;
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .bts-nav-item {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 10px;
      border-radius: var(--radius);
      color: var(--muted);
      background: transparent;
      border: 0;
      text-align: left;
      min-height: 32px;
      justify-content: flex-start;
      margin-bottom: 2px;
    }
    .bts-nav-item.active {
      background: var(--info-bg);
      color: var(--info-text);
    }
    .bts-divider {
      border: 0;
      border-top: .5px solid var(--line);
      margin: 12px 0;
    }
    .bts-main {
      min-width: 0;
      padding: 18px 20px;
    }
    .tab-view[hidden] {
      display: none;
    }
    .dashboard-grid {
      display: grid;
      gap: 14px;
    }
    .section-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--muted);
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .panel {
      background: var(--panel);
      border: .5px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .panel-head {
      min-height: 39px;
      padding: 10px 14px;
      border-bottom: .5px solid var(--line);
      display: flex;
      align-items: center;
      gap: 7px;
      justify-content: space-between;
      color: var(--muted);
      font-size: 11px;
      font-weight: 700;
    }
    .panel-body {
      padding: 12px 14px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }
    .scan-bar {
      background: var(--panel);
      border: .5px solid var(--line);
      border-radius: var(--radius);
      padding: 10px 14px;
      display: grid;
      grid-template-columns: auto 1fr auto auto auto auto;
      gap: 10px;
      align-items: center;
    }
    .scan-label {
      font-size: 11px;
      color: var(--muted);
      white-space: nowrap;
    }
    .checkbox-line {
      display: flex;
      align-items: center;
      gap: 6px;
      min-height: 32px;
      color: var(--muted);
      font-size: 11px;
      font-weight: 600;
    }
    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    .stat-card {
      background: var(--panel);
      border: .5px solid var(--line);
      border-radius: var(--radius);
      padding: 12px 14px;
    }
    .stat-label {
      color: var(--subtle);
      font-size: 11px;
      margin-bottom: 4px;
    }
    .stat-val {
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 22px;
      line-height: 1;
      font-weight: 600;
    }
    .stat-val.ok { color: var(--ok-text); }
    .stat-val.warn { color: var(--warn-text); }
    .stat-val.bad { color: var(--bad-text); }
    .node-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .node-card {
      background: var(--panel);
      border: .5px solid var(--line);
      border-radius: var(--radius);
      padding: 10px 14px;
      display: grid;
      grid-template-columns: 10px minmax(130px, 1fr) auto auto;
      gap: 12px;
      align-items: center;
      cursor: pointer;
    }
    .node-card:hover {
      border-color: var(--line-strong);
    }
    .node-card.selected {
      border-color: var(--info-line);
      background: #fbfdff;
    }
    .pulse-wrap {
      position: relative;
      width: 10px;
      height: 10px;
    }
    .pulse-dot,
    .pulse-ring {
      position: absolute;
      inset: 0;
      border-radius: 50%;
      background: var(--ok-text);
    }
    .pulse-ring {
      animation: pulse-ring 2s ease-out infinite;
      opacity: 0;
    }
    .pulse-dot.warn,
    .pulse-ring.warn { background: var(--warn-text); }
    .pulse-dot.dead,
    .pulse-ring.dead { background: var(--bad-text); }
    @keyframes pulse-ring {
      0% { transform: scale(1); opacity: .5; }
      100% { transform: scale(2.8); opacity: 0; }
    }
    .node-ip {
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      color: var(--text);
    }
    .node-name {
      font-size: 11px;
      color: var(--muted);
      margin-top: 2px;
    }
    .node-badges {
      display: flex;
      gap: 4px;
      justify-content: flex-end;
      flex-wrap: wrap;
    }
    .badge,
    .pill {
      font-family: var(--font-mono);
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      border: .5px solid var(--line);
      color: var(--muted);
      background: var(--panel-alt);
    }
    .badge.ssh,
    .pill.ok,
    button.ok { color: var(--ok-text); border-color: var(--ok-line); background: var(--ok-bg); }
    .badge.tel,
    .pill.info,
    button.info { color: var(--info-text); border-color: var(--info-line); background: var(--info-bg); }
    .badge.bad,
    .pill.bad { color: var(--bad-text); border-color: var(--bad-line); background: var(--bad-bg); }
    .badge.warn,
    .pill.warn { color: var(--warn-text); border-color: var(--warn-line); background: var(--warn-bg); }
    .info-val.ok { color: var(--ok-text); }
    .info-val.info { color: var(--info-text); }
    .info-val.bad { color: var(--bad-text); }
    .info-val.warn { color: var(--warn-text); }
    .node-actions {
      display: flex;
      gap: 4px;
      justify-content: flex-end;
    }
    .icon-btn {
      width: 25px;
      min-width: 25px;
      height: 25px;
      min-height: 25px;
      padding: 0;
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
    }
    .detail-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    .info-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .info-label {
      color: var(--subtle);
      font-size: 10px;
      margin-bottom: 2px;
    }
    .info-val {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text);
      font-weight: 600;
      overflow-wrap: anywhere;
    }
    .action-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 6px;
    }
    .action-grid button {
      min-height: 50px;
      display: flex;
      flex-direction: column;
      gap: 3px;
      align-items: center;
      justify-content: center;
      font-size: 11px;
    }
    .empty-state {
      padding: 18px;
      color: var(--muted);
      border: .5px dashed var(--line);
      border-radius: var(--radius);
      background: var(--panel);
    }
    .status {
      color: var(--muted);
      font-size: 12px;
    }
    .muted { color: var(--muted); }
    .terminal {
      min-height: 210px;
      max-height: 420px;
      overflow: auto;
      padding: 12px;
      background: var(--terminal-bg);
      color: var(--terminal-text);
      border-radius: 0 0 var(--radius) var(--radius);
      white-space: pre-wrap;
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 1.6;
    }
    .terminal.short {
      min-height: 155px;
    }
    .cmd-bar {
      border-top: .5px solid var(--terminal-line);
      padding: 6px 10px;
      background: var(--terminal-panel);
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      gap: 6px;
      align-items: center;
    }
    .cmd-bar input {
      background: transparent;
      border: 0;
      outline: 0;
      color: var(--terminal-text);
      font-family: var(--font-mono);
      font-size: 11px;
      min-height: 26px;
      padding: 2px 4px;
    }
    .template-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      padding: 7px 0;
      border-bottom: .5px solid var(--line);
      font-size: 11px;
    }
    .template-row:last-child { border-bottom: 0; }
    .scan-progress-wrap {
      background: var(--panel-alt);
      border: .5px solid var(--line);
      border-radius: 4px;
      height: 4px;
      overflow: hidden;
      margin-bottom: 7px;
    }
    .scan-progress-bar {
      height: 100%;
      width: 0;
      border-radius: 4px;
      background: var(--info-text);
      transition: width .35s ease;
    }
    .scan-progress-bar.scanning {
      animation: scan-fill 1.1s ease-in-out infinite alternate;
    }
    @keyframes scan-fill {
      from { width: 15%; }
      to { width: 100%; }
    }
    .scan-progress-label {
      font-family: var(--font-mono);
      font-size: 10px;
      color: var(--subtle);
      display: flex;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .scan-grid {
      display: grid;
      grid-template-columns: repeat(16, minmax(0, 1fr));
      gap: 4px;
      margin-bottom: 12px;
    }
    .scan-cell {
      aspect-ratio: 1;
      border-radius: 3px;
      background: var(--panel-alt);
      border: .5px solid var(--line);
      opacity: .5;
    }
    .scan-cell.active {
      background: var(--info-bg);
      border-color: var(--info-line);
      opacity: 1;
    }
    .scan-cell.found {
      background: var(--ok-bg);
      border-color: var(--ok-line);
      opacity: 1;
    }
    .scan-results {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    .scan-result-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 10px;
      background: var(--panel);
      border: .5px solid var(--line);
      border-radius: 5px;
      font-size: 11px;
    }
    @media (max-width: 1120px) {
      .bts-body { grid-template-columns: 1fr; }
      .bts-sidebar { display: none; }
      .detail-grid { grid-template-columns: 1fr; }
      .form-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .scan-bar { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 720px) {
      .bts-header {
        align-items: flex-start;
        flex-direction: column;
      }
      .bts-header-right {
        width: 100%;
        margin-left: 0;
        flex-wrap: wrap;
      }
      .bts-main { padding: 12px; }
      .stats-row,
      .form-grid,
      .scan-bar,
      .action-grid,
      .info-grid { grid-template-columns: 1fr; }
      .node-card { grid-template-columns: 10px 1fr; }
      .node-badges,
      .node-actions { justify-content: flex-start; grid-column: 2; }
      button { white-space: normal; }
    }
  </style>
</head>
<body>
  <div class="bts-root">
    <header class="bts-header">
      <div class="bts-logo">
        <div class="bts-signal-icon">B</div>
        <div>
          <div class="bts-logo-text">BTS Cluster</div>
          <div class="bts-logo-sub">YateBTS · Node Manager</div>
        </div>
      </div>
      <div class="bts-header-right">
        <div id="headerSubnet" class="bts-subnet-pill">subnet: ...</div>
        <span id="sshpassState" class="status">sshpass: ...</span>
        <button id="refreshBtn">Refresh</button>
        <button class="app-tab active" data-view="add" role="tab" aria-selected="true">Scan / Add</button>
        <button class="app-tab" data-view="work" role="tab" aria-selected="false">Dashboard</button>
      </div>
    </header>

    <div class="bts-body">
      <aside class="bts-sidebar">
        <div class="bts-sidebar-section">
          <div class="bts-sidebar-label">Navigation</div>
          <button class="bts-nav-item active app-tab" data-view="add" role="tab" aria-selected="true">Scan / Add</button>
          <button class="bts-nav-item app-tab" data-view="work" role="tab" aria-selected="false">Nodes</button>
          <button class="bts-nav-item" data-focus-panel="console">Telnet console</button>
          <button class="bts-nav-item" data-focus-panel="logs">Live logs</button>
        </div>
        <hr class="bts-divider">
        <div class="bts-sidebar-section">
          <div class="bts-sidebar-label">Selected node</div>
          <div id="selectedNode" class="muted">No node selected</div>
        </div>
      </aside>

      <main class="bts-main">
        <div id="addView" class="tab-view dashboard-grid">
          <div class="panel">
            <div class="panel-head">
              <span>Subnet scan</span>
              <span id="scanState" class="status"></span>
            </div>
            <div class="panel-body">
              <div class="scan-bar">
                <span class="scan-label">CIDR</span>
                <input id="scanCidr" placeholder="192.168.1.0/24">
                <label class="checkbox-line"><input id="scanAutoAdd" type="checkbox" checked> Auto-add</label>
                <label class="checkbox-line">SSH <input id="scanSshPort" type="number" value="22" min="1" max="65535"></label>
                <label class="checkbox-line">Yate <input id="scanTelnetPort" type="number" value="5038" min="1" max="65535"></label>
                <button id="scanBtn" class="primary">Scan subnet</button>
              </div>
              <div class="form-grid" style="margin-top: 10px">
                <label>SSH login
                  <input id="scanUser" value="pi">
                </label>
                <label>SSH password
                  <input id="scanPassword" type="password" value="raspberry">
                </label>
              </div>
              <div class="panel" style="margin-top: 12px">
                <div class="panel-body">
                  <div class="scan-progress-wrap"><div id="scanBar" class="scan-progress-bar"></div></div>
                  <div class="scan-progress-label">
                    <span id="scanProgressText">idle</span>
                    <span id="scanFoundText">0 found</span>
                  </div>
                  <div id="scanGrid" class="scan-grid"></div>
                  <div id="scanResults" class="scan-results"></div>
                </div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <span>Manual add</span>
              <span id="addState" class="status"></span>
            </div>
            <div class="panel-body">
              <div class="form-grid">
                <label>Name
                  <input id="addName" placeholder="bts-1">
                </label>
                <label>IP
                  <input id="addIp" placeholder="192.168.1.50">
                </label>
                <label>SSH login
                  <input id="addUser" value="pi">
                </label>
                <label>SSH password
                  <input id="addPassword" type="password" value="raspberry">
                </label>
                <label>Service
                  <input id="addService" value="yate.service">
                </label>
                <label>Radio.Band
                  <input id="addRadioBand" placeholder="900">
                </label>
                <label>Radio.C0
                  <input id="addRadioC0" type="number" min="0" max="1023" placeholder="62">
                </label>
                <label>MS.IP.Base
                  <input id="addMsIpBase" placeholder="192.168.99.1">
                </label>
                <label>MS.IP.MaxCount
                  <input id="addMsIpMaxCount" type="number" min="1" max="65535" placeholder="254">
                </label>
                <div class="toolbar">
                  <button id="addBtn" class="primary">Add node</button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div id="workView" class="tab-view dashboard-grid" hidden>
          <div class="stats-row">
            <div class="stat-card"><div class="stat-label">Total nodes</div><div id="statTotal" class="stat-val">0</div></div>
            <div class="stat-card"><div class="stat-label">Online</div><div id="statOnline" class="stat-val ok">0</div></div>
            <div class="stat-card"><div class="stat-label">Warning</div><div id="statWarn" class="stat-val warn">0</div></div>
            <div class="stat-card"><div class="stat-label">Offline</div><div id="statOffline" class="stat-val bad">0</div></div>
          </div>

          <div>
            <div class="section-title">
              <span>Discovered nodes</span>
              <span id="nodeState" class="status"></span>
            </div>
            <div id="nodeEmpty" class="empty-state" hidden>No nodes yet. Open Scan / Add to add one.</div>
            <div id="nodesBody" class="node-list"></div>
          </div>

          <div class="detail-grid">
            <div class="panel">
              <div class="panel-head"><span>Node info</span><span id="selectedNodeState" class="status"></span></div>
              <div id="nodeInfo" class="panel-body info-grid"></div>
            </div>

            <div class="panel">
              <div class="panel-head"><span>Service control</span><span id="actionState" class="status"></span></div>
              <div class="panel-body action-grid">
                <button data-action="start" class="ok">Start</button>
                <button data-action="restart" class="primary">Restart</button>
                <button data-action="stop" class="danger">Stop</button>
                <button data-action="configure-rmanager-addr" class="info">Telnet bind</button>
              </div>
            </div>

            <div id="consolePanel" class="panel">
              <div class="panel-head"><span>Yate telnet console</span><span id="telnetState" class="status"></span></div>
              <div id="terminal" class="terminal"></div>
              <div class="cmd-bar">
                <span style="font-family: var(--font-mono); color: var(--terminal-blue);">&gt;</span>
                <input id="telnetCommand" value="mbts sgsn list">
                <button id="sendTelnetBtn" class="primary">Send</button>
                <button id="clearOutputBtn">Clear</button>
              </div>
              <div class="panel-body">
                <div id="templates"></div>
              </div>
            </div>

            <div id="logsPanel" class="panel">
              <div class="panel-head"><span>Live log stream</span><span id="logState" class="status"></span></div>
              <div class="panel-body form-grid">
                <label>File
                  <input id="logPath" value="/var/log/yate.err">
                </label>
                <label>Last lines
                  <input id="logLines" type="number" value="200" min="0" max="2000">
                </label>
                <label class="checkbox-line">
                  <input id="logSudo" type="checkbox"> Read through sudo
                </label>
                <div class="toolbar">
                  <button id="startLogBtn" class="primary">Start tail</button>
                  <button id="stopLogBtn">Stop</button>
                  <button id="clearLogBtn">Clear</button>
                </div>
              </div>
              <div id="logTerminal" class="terminal short"></div>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>

  <script>
    const state = { nodes: [], selectedId: null, templates: [], logSource: null };
    const $ = (id) => document.getElementById(id);

    function esc(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[ch]));
    }

    async function api(path, options = {}) {
      const init = { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } };
      if (init.body && typeof init.body !== "string") init.body = JSON.stringify(init.body);
      const res = await fetch(path, init);
      const data = await res.json();
      if (!res.ok || (data.ok === false && !("result" in data) && !("output" in data))) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      return data;
    }

    function showView(name) {
      document.querySelectorAll(".tab-view").forEach((view) => {
        view.hidden = view.id !== `${name}View`;
      });
      document.querySelectorAll(".app-tab").forEach((tab) => {
        const active = tab.dataset.view === name;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", active ? "true" : "false");
      });
    }

    function pill(text, kind) {
      return `<span class="pill ${kind}">${esc(text)}</span>`;
    }

    function statusKind(node) {
      const live = node.live || {};
      if (!live.online) return "dead";
      if (live.service && live.service !== "active") return "warn";
      if (!live.telnet_open || live.auth_ok === false) return "warn";
      return "ok";
    }

    function statusLabel(node) {
      const live = node.live || {};
      if (!live.online) return "unreachable";
      if (live.service && live.service !== "active") return `yate.service ${live.service}`;
      if (!live.telnet_open) return "telnet closed";
      return "yate.service active";
    }

    function effectiveNodeValue(node, field) {
      const live = node.live || {};
      return node[field] || live[field] || "";
    }

    function renderStats() {
      const total = state.nodes.length;
      const online = state.nodes.filter((node) => node.live?.online).length;
      const warn = state.nodes.filter((node) => statusKind(node) === "warn").length;
      const offline = state.nodes.filter((node) => statusKind(node) === "dead").length;
      $("statTotal").textContent = total;
      $("statOnline").textContent = online;
      $("statWarn").textContent = warn;
      $("statOffline").textContent = offline;
    }

    function renderNodes() {
      const body = $("nodesBody");
      const empty = $("nodeEmpty");
      if (!state.nodes.length) {
        body.innerHTML = "";
        empty.hidden = false;
        renderStats();
        return;
      }
      empty.hidden = true;
      body.innerHTML = state.nodes.map((node) => {
        const live = node.live || {};
        const kind = statusKind(node);
        const pulse = kind === "ok" ? "" : kind;
        const label = statusLabel(node);
        const radioBand = effectiveNodeValue(node, "radio_band");
        const radioC0 = effectiveNodeValue(node, "radio_c0");
        const msIpBase = effectiveNodeValue(node, "ms_ip_base");
        const msIpMaxCount = effectiveNodeValue(node, "ms_ip_max_count");
        const radio = radioBand && radioC0 ? `${radioBand} / C0 ${radioC0}` : "radio unset";
        const msPool = msIpBase && msIpMaxCount ? `MS ${msIpBase} x${msIpMaxCount}` : "MS pool unset";
        const conflicts = node.conflicts || [];
        const serviceBadge = live.service === "active"
          ? `<span class="badge ssh">active</span>`
          : `<span class="badge ${kind === "dead" ? "bad" : "warn"}">${esc(live.service || "unknown")}</span>`;
        return `
          <div class="node-card ${node.id === state.selectedId ? "selected" : ""}" data-id="${esc(node.id)}">
            <div class="pulse-wrap"><div class="pulse-ring ${pulse}"></div><div class="pulse-dot ${pulse}"></div></div>
            <div>
              <div class="node-ip">${esc(node.ip)}</div>
              <div class="node-name">${esc(node.name || live.hostname || "bts node")} · ${esc(label)} · ${esc(radio)} · ${esc(msPool)}</div>
            </div>
            <div class="node-badges">
              ${live.ssh_open ? `<span class="badge ssh">SSH</span>` : `<span class="badge bad">no ssh</span>`}
              ${live.telnet_open ? `<span class="badge tel">:${esc(node.telnet_port)}</span>` : `<span class="badge warn">tel closed</span>`}
              ${serviceBadge}
              ${conflicts.length ? `<span class="badge bad">conflict</span>` : ""}
            </div>
            <div class="node-actions">
              <button class="icon-btn" data-select="${esc(node.id)}" title="Focus">F</button>
              <button class="icon-btn" data-delete="${esc(node.id)}" title="Delete">D</button>
            </div>
          </div>
        `;
      }).join("");
      body.querySelectorAll("[data-select]").forEach((btn) => {
        btn.addEventListener("click", () => selectNode(btn.dataset.select));
      });
      body.querySelectorAll("[data-delete]").forEach((btn) => {
        btn.addEventListener("click", (event) => event.stopPropagation());
        btn.addEventListener("click", () => deleteNode(btn.dataset.delete));
      });
      body.querySelectorAll(".node-card[data-id]").forEach((card) => {
        card.addEventListener("click", () => selectNode(card.dataset.id));
      });
      renderStats();
    }

    function renderNodeInfo(node) {
      const info = $("nodeInfo");
      if (!node) {
        info.innerHTML = `<div class="muted">Select a node to inspect live status.</div>`;
        $("selectedNodeState").textContent = "";
        return;
      }
      const live = node.live || {};
      const sshClass = live.ssh_open ? "ok" : "bad";
      const telClass = live.telnet_open ? "ok" : "warn";
      const svcClass = live.service === "active" ? "ok" : live.service === "unknown" ? "warn" : "bad";
      const conflicts = node.conflicts || [];
      const radioBand = effectiveNodeValue(node, "radio_band");
      const radioC0 = effectiveNodeValue(node, "radio_c0");
      const msIpBase = effectiveNodeValue(node, "ms_ip_base");
      const msIpMaxCount = effectiveNodeValue(node, "ms_ip_max_count");
      $("selectedNodeState").textContent = `${node.ip}:${node.telnet_port}`;
      info.innerHTML = `
        <div><div class="info-label">IP address</div><div class="info-val">${esc(node.ip)}</div></div>
        <div><div class="info-label">Hostname</div><div class="info-val">${esc(live.hostname || node.name || "-")}</div></div>
        <div><div class="info-label">SSH port</div><div class="info-val ${sshClass}">:${esc(node.ssh_port)} ${live.ssh_open ? "open" : "closed"}</div></div>
        <div><div class="info-label">Yate telnet</div><div class="info-val ${telClass}">:${esc(node.telnet_port)} ${live.telnet_open ? "open" : "closed"}</div></div>
        <div><div class="info-label">Service</div><div class="info-val ${svcClass}">${esc(live.service || "unknown")}</div></div>
        <div><div class="info-label">Credentials</div><div class="info-val">${esc(node.user)} / ${node.has_password ? "stored" : "key"}</div></div>
        <div><div class="info-label">Radio.Band</div><div class="info-val">${esc(radioBand || "-")}</div></div>
        <div><div class="info-label">Radio.C0</div><div class="info-val">${esc(radioC0 || "-")}</div></div>
        <div><div class="info-label">MS.IP.Base</div><div class="info-val">${esc(msIpBase || "-")}</div></div>
        <div><div class="info-label">MS.IP.MaxCount</div><div class="info-val">${esc(msIpMaxCount || "-")}</div></div>
        <div style="grid-column: 1 / -1"><div class="info-label">Conflicts</div><div class="info-val ${conflicts.length ? "bad" : "ok"}">${esc(conflicts.join("; ") || "none")}</div></div>
      `;
    }

    function renderSelected() {
      const node = state.nodes.find((item) => item.id === state.selectedId);
      $("selectedNode").innerHTML = node
        ? `<strong>${esc(node.name)}</strong> <span class="muted">${esc(node.ip)} / ${esc(node.service)}</span>`
        : "No node selected";
      renderNodeInfo(node);
      renderNodes();
    }

    function selectNode(id) {
      if (state.selectedId && state.selectedId !== id) stopLogTail(false);
      state.selectedId = id;
      renderSelected();
    }

    function buildScanGrid(activeCount = 0, foundIps = []) {
      const grid = $("scanGrid");
      const foundCells = new Set(foundIps.map((ip) => (Number(String(ip).split(".").pop()) - 1) % 64));
      grid.innerHTML = Array.from({ length: 64 }, (_, index) => {
        const cls = foundCells.has(index) ? "found" : index < activeCount ? "active" : "";
        return `<div class="scan-cell ${cls}"></div>`;
      }).join("");
    }

    function renderScanResults(discoveries) {
      $("scanResults").innerHTML = (discoveries || []).map((item) => {
        const ssh = item.ssh_open ? `<span class="badge ssh">SSH</span>` : "";
        const tel = item.telnet_open ? `<span class="badge tel">:${esc($("scanTelnetPort").value || 5038)}</span>` : "";
        const service = item.service ? `<span class="muted">${esc(item.service)}</span>` : "";
        return `
          <div class="scan-result-row">
            <span class="node-ip">${esc(item.ip)}</span>
            ${ssh}${tel}${service}
          </div>
        `;
      }).join("");
    }

    function setScanIdle() {
      $("scanBar").classList.remove("scanning");
      $("scanBar").style.width = "0%";
      $("scanProgressText").textContent = "idle";
      $("scanFoundText").textContent = "0 found";
      buildScanGrid();
      renderScanResults([]);
    }

    async function loadConfig() {
      const data = await api("/api/config");
      $("scanCidr").value = data.default_cidr;
      $("headerSubnet").textContent = data.default_cidr;
      $("sshpassState").textContent = data.sshpass ? "sshpass: ok" : "sshpass: missing";
      state.templates = data.templates || [];
      $("templates").innerHTML = state.templates.map((tpl) => `
        <div class="template-row">
          <div><strong>${esc(tpl.name)}</strong><div class="muted">${esc(tpl.command)}</div></div>
          <button data-template="${esc(tpl.command)}">Insert</button>
        </div>
      `).join("");
      $("templates").querySelectorAll("[data-template]").forEach((btn) => {
        btn.addEventListener("click", () => { $("telnetCommand").value = btn.dataset.template; });
      });
      setScanIdle();
    }

    async function loadNodes() {
      $("nodeState").textContent = "checking...";
      const data = await api("/api/nodes");
      state.nodes = data.nodes || [];
      if (state.selectedId && !state.nodes.some((node) => node.id === state.selectedId)) {
        state.selectedId = null;
      }
      if (!state.selectedId && state.nodes.length) state.selectedId = state.nodes[0].id;
      $("nodeState").textContent = `${state.nodes.length} node${state.nodes.length === 1 ? "" : "s"}`;
      renderSelected();
    }

    async function scan() {
      $("scanBtn").disabled = true;
      $("scanState").textContent = "scanning...";
      $("scanBar").classList.add("scanning");
      $("scanProgressText").textContent = `${$("scanCidr").value || "subnet"} · checking SSH and Yate`;
      $("scanFoundText").textContent = "scanning";
      $("scanResults").innerHTML = "";
      buildScanGrid(64);
      try {
        const data = await api("/api/scan", {
          method: "POST",
          body: {
            cidr: $("scanCidr").value,
            user: $("scanUser").value,
            password: $("scanPassword").value,
            ssh_port: Number($("scanSshPort").value || 22),
            telnet_port: Number($("scanTelnetPort").value || 5038),
            auto_add: $("scanAutoAdd").checked
          }
        });
        const discoveries = data.discoveries || [];
        $("scanState").textContent = `found: ${discoveries.length}`;
        $("scanBar").classList.remove("scanning");
        $("scanBar").style.width = "100%";
        $("scanProgressText").textContent = "scan complete";
        $("scanFoundText").textContent = `${discoveries.length} found`;
        buildScanGrid(64, discoveries.map((item) => item.ip));
        renderScanResults(discoveries);
        await loadNodes();
      } catch (err) {
        $("scanState").textContent = err.message;
        $("scanBar").classList.remove("scanning");
        $("scanBar").style.width = "0%";
        $("scanProgressText").textContent = "scan failed";
      } finally {
        $("scanBtn").disabled = false;
      }
    }

    async function addNode() {
      $("addState").textContent = "adding...";
      try {
        const data = await api("/api/nodes", {
          method: "POST",
          body: {
            name: $("addName").value,
            ip: $("addIp").value,
            user: $("addUser").value,
            password: $("addPassword").value,
            service: $("addService").value,
            radio_band: $("addRadioBand").value,
            radio_c0: $("addRadioC0").value,
            ms_ip_base: $("addMsIpBase").value,
            ms_ip_max_count: $("addMsIpMaxCount").value
          }
        });
        state.selectedId = data.node.id;
        $("addState").textContent = "saved";
        await loadNodes();
        showView("work");
      } catch (err) {
        $("addState").textContent = err.message;
      }
    }

    async function deleteNode(id) {
      await api(`/api/nodes/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (state.selectedId === id) state.selectedId = null;
      await loadNodes();
    }

    async function serviceAction(action) {
      const node = state.nodes.find((item) => item.id === state.selectedId);
      if (!node) {
        $("actionState").textContent = "select a node";
        return;
      }
      const actionText = action === "configure-rmanager-addr"
        ? "configure telnet bind"
        : action;
      const shownCommand = action === "configure-rmanager-addr"
        ? `set ${node.service} rmanager addr=0.0.0.0; restart ${node.service}`
        : `systemctl ${action} ${node.service}`;
      $("actionState").textContent = `${actionText}...`;
      try {
        const data = await api(`/api/nodes/${encodeURIComponent(node.id)}/action`, {
          method: "POST",
          body: { action }
        });
        const result = data.result || {};
        $("actionState").textContent = result.ok ? "done" : `error rc=${result.rc}`;
        writeOutput(`$ ${shownCommand}\n${result.stdout || ""}${result.stderr || ""}\n`);
        await loadNodes();
      } catch (err) {
        $("actionState").textContent = `${actionText}: ${err.message}`;
      }
    }

    function writeOutput(text) {
      const terminal = $("terminal");
      terminal.textContent += text;
      terminal.scrollTop = terminal.scrollHeight;
    }

    function writeLogOutput(text) {
      const terminal = $("logTerminal");
      terminal.textContent += text;
      terminal.scrollTop = terminal.scrollHeight;
    }

    function stopLogTail(updateStatus = true) {
      if (state.logSource) {
        state.logSource.close();
        state.logSource = null;
      }
      if (updateStatus) $("logState").textContent = "stopped";
    }

    function startLogTail() {
      const node = state.nodes.find((item) => item.id === state.selectedId);
      if (!node) {
        $("logState").textContent = "select a node";
        return;
      }
      stopLogTail(false);
      const params = new URLSearchParams({
        path: $("logPath").value || "/var/log/yate.err",
        lines: $("logLines").value || "200",
        sudo: $("logSudo").checked ? "1" : "0"
      });
      const url = `/api/nodes/${encodeURIComponent(node.id)}/logs/stream?${params.toString()}`;
      const source = new EventSource(url);
      state.logSource = source;
      $("logState").textContent = `reading ${node.name}`;
      writeLogOutput(`\n[${node.name} ${node.ip}] tail -F ${$("logPath").value || "/var/log/yate.err"}\n`);
      source.addEventListener("status", (event) => {
        const data = JSON.parse(event.data);
        $("logState").textContent = data.message || "connected";
      });
      source.addEventListener("line", (event) => {
        const data = JSON.parse(event.data);
        writeLogOutput(`${data.text}\n`);
      });
      source.addEventListener("exit", (event) => {
        const data = JSON.parse(event.data);
        $("logState").textContent = `tail exited rc=${data.rc}`;
        stopLogTail(false);
      });
      source.addEventListener("logerror", (event) => {
        if (event.data) {
          try {
            const data = JSON.parse(event.data);
            writeLogOutput(`ERROR: ${data.message}\n`);
          } catch (_) {}
        }
        $("logState").textContent = "read error";
        stopLogTail(false);
      });
      source.onerror = () => {
        $("logState").textContent = "log stream closed";
        stopLogTail(false);
      };
    }

    async function sendTelnet() {
      const node = state.nodes.find((item) => item.id === state.selectedId);
      if (!node) {
        $("telnetState").textContent = "select a node";
        return;
      }
      const command = $("telnetCommand").value;
      $("telnetState").textContent = "sending...";
      try {
        const data = await api(`/api/nodes/${encodeURIComponent(node.id)}/telnet`, {
          method: "POST",
          body: { command }
        });
        $("telnetState").textContent = data.ok ? "done" : "error";
        writeOutput(`\n[${node.name} ${node.ip}] $ ${command}\n${data.output || data.error || ""}\n`);
      } catch (err) {
        $("telnetState").textContent = err.message;
      }
    }

    $("refreshBtn").addEventListener("click", loadNodes);
    $("scanBtn").addEventListener("click", scan);
    $("addBtn").addEventListener("click", addNode);
    $("sendTelnetBtn").addEventListener("click", sendTelnet);
    $("clearOutputBtn").addEventListener("click", () => { $("terminal").textContent = ""; });
    $("startLogBtn").addEventListener("click", startLogTail);
    $("stopLogBtn").addEventListener("click", () => stopLogTail(true));
    $("clearLogBtn").addEventListener("click", () => { $("logTerminal").textContent = ""; });
    document.querySelectorAll(".app-tab").forEach((tab) => {
      tab.addEventListener("click", () => showView(tab.dataset.view));
    });
    document.querySelectorAll("[data-focus-panel]").forEach((btn) => {
      btn.addEventListener("click", () => {
        showView("work");
        const target = btn.dataset.focusPanel === "logs" ? $("logsPanel") : $("consolePanel");
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
    document.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => serviceAction(btn.dataset.action));
    });

    (async function boot() {
      try {
        await loadConfig();
        await loadNodes();
      } catch (err) {
        $("nodeState").textContent = err.message;
      }
    })();
  </script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the BTS cluster web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8097, help="Bind port")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), App)
    print(f"BTS Cluster Web: http://{args.host}:{args.port}/")
    print(f"Inventory: {INVENTORY_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
