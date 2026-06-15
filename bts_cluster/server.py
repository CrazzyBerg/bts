#!/usr/bin/env python3
"""
Local web UI for a small YateBTS Raspberry Pi cluster.

The server intentionally uses only the Python standard library so it can run on
a controller machine without installing npm or pip dependencies.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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


def run_service_action(node: Node, action: str) -> dict[str, Any]:
    if action not in {"start", "restart", "stop"}:
        raise ValueError("Unsupported service action")
    if not SERVICE_RE.match(node.service):
        raise ValueError("Invalid service name")
    service = node.service
    if node.password:
        password = node.password.replace("'", "'\"'\"'")
        remote = f"printf '%s\\n' '{password}' | sudo -S -p '' systemctl {action} {service}"
    else:
        remote = f"sudo -n systemctl {action} {service}"
    return run_ssh(node, remote, timeout=25)


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


def service_status(node: Node) -> dict[str, Any]:
    command = (
        "printf 'hostname='; hostname 2>/dev/null || true; "
        f"printf 'service='; systemctl is-active {node.service} 2>/dev/null || true"
    )
    result = run_ssh(node, command, timeout=7, batch=not bool(node.password))
    hostname = ""
    service = "unknown"
    if result["stdout"]:
        for line in result["stdout"].splitlines():
            if line.startswith("hostname="):
                hostname = line.split("=", 1)[1].strip()
            elif line.startswith("service="):
                service = line.split("=", 1)[1].strip() or "unknown"
    return {"hostname": hostname, "service": service, "ssh": result}


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
            if not status["ssh"]["ok"]:
                info["auth_error"] = compact_error(status["ssh"]["stderr"])
        except RuntimeError as exc:
            info["auth_ok"] = None
            info["auth_error"] = str(exc)
    return info


def compact_error(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1][:240]


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


def node_public(node: Node, live: dict[str, Any] | None = None) -> dict[str, Any]:
    data = asdict(node)
    data.pop("password", None)
    data["has_password"] = bool(node.password)
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
            json_response(
                self,
                HTTPStatus.OK,
                {"ok": True, "nodes": [node_public(node, live_by_id.get(node.id)) for node in nodes]},
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
        if not SERVICE_RE.match(node.service):
            raise ValueError("Invalid service name")
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
            json_response(self, HTTPStatus.OK, {"ok": False, "output": "", "error": str(exc)})
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
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1e2329;
      --muted: #667080;
      --line: #dfe4ea;
      --blue: #2563eb;
      --green: #168354;
      --red: #c73535;
      --amber: #a76705;
      --shadow: 0 1px 3px rgba(20, 30, 44, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      letter-spacing: 0;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 4;
    }
    .bar {
      max-width: 1280px;
      margin: 0 auto;
      min-height: 58px;
      padding: 10px 18px;
      display: flex;
      align-items: center;
      gap: 16px;
      justify-content: space-between;
    }
    h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
    }
    main {
      max-width: 1280px;
      margin: 0 auto;
      padding: 18px;
      display: grid;
      gap: 16px;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .section-head {
      min-height: 48px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    h2 {
      margin: 0;
      font-size: 15px;
      font-weight: 700;
    }
    .content { padding: 14px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }
    label {
      color: var(--muted);
      display: grid;
      gap: 5px;
      font-size: 12px;
      font-weight: 650;
    }
    input, select, textarea {
      width: 100%;
      border: 1px solid #cfd6df;
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      padding: 8px 9px;
      min-height: 36px;
    }
    textarea {
      min-height: 128px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
    }
    input[type="checkbox"] { width: auto; min-height: 0; }
    button {
      border: 1px solid #b9c2ce;
      background: #fff;
      color: var(--text);
      border-radius: 6px;
      min-height: 36px;
      padding: 7px 11px;
      font: inherit;
      font-weight: 650;
      cursor: pointer;
      white-space: nowrap;
    }
    button.primary {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
    }
    button.danger {
      color: #fff;
      background: var(--red);
      border-color: var(--red);
    }
    button:disabled {
      opacity: .55;
      cursor: not-allowed;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .app-tabs {
      display: flex;
      align-items: flex-end;
      gap: 4px;
      border-bottom: 1px solid var(--line);
      min-width: 240px;
    }
    .app-tab {
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
      border-color: transparent;
      background: transparent;
      color: var(--muted);
      min-height: 38px;
      padding: 7px 14px;
    }
    .app-tab.active {
      background: var(--bg);
      color: var(--text);
      border-color: var(--line);
      border-bottom-color: var(--bg);
      margin-bottom: -1px;
    }
    .tab-view[hidden] { display: none; }
    .node-tabs {
      display: flex;
      align-items: flex-end;
      gap: 3px;
      padding: 10px 14px 0;
      border-bottom: 1px solid var(--line);
      overflow-x: auto;
      background: #f8fafc;
    }
    .node-tab {
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
      border-color: #cfd6df;
      background: #edf1f5;
      color: #3b4653;
      min-width: 150px;
      max-width: 230px;
      justify-content: flex-start;
      text-align: left;
      margin-bottom: -1px;
    }
    .node-tab.active {
      background: var(--panel);
      color: var(--text);
      border-bottom-color: var(--panel);
      box-shadow: 0 -1px 2px rgba(20, 30, 44, .05);
    }
    .node-tab-title,
    .node-tab-meta {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      line-height: 1.2;
    }
    .node-tab-meta {
      color: var(--muted);
      font-size: 11px;
      font-weight: 600;
      margin-top: 2px;
    }
    .node-dot {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-right: 6px;
      background: var(--muted);
      vertical-align: 1px;
    }
    .empty-state {
      padding: 18px 14px;
      color: var(--muted);
    }
    .status {
      color: var(--muted);
      font-size: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 9px 8px;
      vertical-align: middle;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 750;
      background: #fbfcfd;
    }
    tr.selected { background: #eef5ff; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 750;
      border: 1px solid transparent;
    }
    .ok { color: #0f6842; background: #e8f7ef; border-color: #bfe8d2; }
    .bad { color: #9e2222; background: #fdecec; border-color: #f5c1c1; }
    .warn { color: #804d00; background: #fff4df; border-color: #f2d69c; }
    .node-dot.ok { background: var(--green); border-color: transparent; }
    .node-dot.bad { background: var(--red); border-color: transparent; }
    .muted { color: var(--muted); }
    .terminal {
      min-height: 220px;
      max-height: 420px;
      overflow: auto;
      padding: 12px;
      background: #101419;
      color: #d8e2ed;
      border-radius: 6px;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.45;
    }
    .split {
      display: grid;
      grid-template-columns: 1.15fr .85fr;
      gap: 16px;
      align-items: start;
    }
    .template-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid var(--line);
    }
    .template-row:last-child { border-bottom: 0; }
    .checkbox-line {
      min-height: 36px;
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text);
      font-size: 13px;
      font-weight: 650;
    }
    @media (max-width: 980px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .split { grid-template-columns: 1fr; }
      table { table-layout: auto; }
    }
    @media (max-width: 640px) {
      .bar, main { padding-left: 10px; padding-right: 10px; }
      .bar { align-items: flex-start; flex-direction: column; }
      .app-tabs { width: 100%; }
      .grid { grid-template-columns: 1fr; }
      th:nth-child(4), td:nth-child(4),
      th:nth-child(5), td:nth-child(5) { display: none; }
      .section-head { align-items: flex-start; flex-direction: column; }
      .toolbar { width: 100%; }
      button { white-space: normal; }
    }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <h1>BTS Cluster</h1>
      <div class="app-tabs" role="tablist" aria-label="Main navigation">
        <button class="app-tab active" data-view="add" role="tab" aria-selected="true">Add / Discover</button>
        <button class="app-tab" data-view="work" role="tab" aria-selected="false">Work</button>
      </div>
      <div class="toolbar">
        <span id="sshpassState" class="status">sshpass: ...</span>
        <button id="refreshBtn">Refresh</button>
      </div>
    </div>
  </header>

  <main>
    <div id="addView" class="tab-view">
      <section>
        <div class="section-head">
          <h2>Subnet Discovery</h2>
          <span id="scanState" class="status"></span>
        </div>
        <div class="content">
          <div class="grid">
            <label>CIDR
              <input id="scanCidr" placeholder="192.168.1.0/24">
            </label>
            <label>SSH login
              <input id="scanUser" value="pi">
            </label>
            <label>SSH password
              <input id="scanPassword" type="password" value="raspberry">
            </label>
            <label>SSH port
              <input id="scanSshPort" type="number" value="22" min="1" max="65535">
            </label>
            <label>Telnet port
              <input id="scanTelnetPort" type="number" value="5038" min="1" max="65535">
            </label>
            <label class="checkbox-line">
              <input id="scanAutoAdd" type="checkbox" checked>
              Auto-add discovered nodes
            </label>
          </div>
          <div class="toolbar" style="margin-top: 10px">
            <button id="scanBtn" class="primary">Scan subnet</button>
          </div>
        </div>
      </section>

      <section>
        <div class="section-head">
          <h2>Manual Add</h2>
          <span id="addState" class="status"></span>
        </div>
        <div class="content">
          <div class="grid">
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
            <div class="toolbar">
              <button id="addBtn" class="primary">Add node</button>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div id="workView" class="tab-view" hidden>
      <section>
        <div id="nodeTabs" class="node-tabs"></div>
        <div id="nodeEmpty" class="empty-state" hidden>No nodes yet. Open Add / Discover to add one.</div>
      </section>

      <div class="split">
        <section>
          <div class="section-head">
            <h2>Node Overview</h2>
            <span id="nodeState" class="status"></span>
          </div>
          <div class="content" style="padding: 0">
            <table>
              <thead>
                <tr>
                  <th style="width: 20%">Name</th>
                  <th style="width: 16%">IP</th>
                  <th style="width: 15%">Online</th>
                  <th style="width: 14%">Yate</th>
                  <th style="width: 17%">Access</th>
                  <th style="width: 18%">Actions</th>
                </tr>
              </thead>
              <tbody id="nodesBody"></tbody>
            </table>
          </div>
        </section>

        <section>
          <div class="section-head">
            <h2>Service</h2>
            <span id="actionState" class="status"></span>
          </div>
          <div class="content">
            <div id="selectedNode" class="muted">No node selected</div>
            <div class="toolbar" style="margin-top: 12px">
              <button data-action="start">Start</button>
              <button data-action="restart" class="primary">Restart</button>
              <button data-action="stop" class="danger">Stop</button>
            </div>
          </div>
        </section>
      </div>

      <section>
        <div class="section-head">
          <h2>Logs</h2>
          <span id="logState" class="status"></span>
        </div>
        <div class="content">
          <div class="grid">
            <label>File
              <input id="logPath" value="/var/log/yate.err">
            </label>
            <label>Last lines
              <input id="logLines" type="number" value="200" min="0" max="2000">
            </label>
            <label class="checkbox-line">
              <input id="logSudo" type="checkbox">
              Read through sudo
            </label>
            <div class="toolbar">
              <button id="startLogBtn" class="primary">Start tail</button>
              <button id="stopLogBtn">Stop</button>
              <button id="clearLogBtn">Clear</button>
            </div>
          </div>
          <div id="logTerminal" class="terminal" style="margin-top: 12px"></div>
        </div>
      </section>

      <section>
        <div class="section-head">
          <h2>Telnet Commands</h2>
          <span id="telnetState" class="status"></span>
        </div>
        <div class="content split">
          <div>
            <label>Command
              <input id="telnetCommand" value="mbts sgsn list">
            </label>
            <div class="toolbar" style="margin: 10px 0">
              <button id="sendTelnetBtn" class="primary">Send</button>
              <button id="clearOutputBtn">Clear</button>
            </div>
            <div id="terminal" class="terminal"></div>
          </div>
          <div>
            <h2 style="margin-bottom: 6px">Templates</h2>
            <div id="templates"></div>
          </div>
        </div>
      </section>
    </div>
  </main>

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

    function pill(text, kind) {
      return `<span class="pill ${kind}">${esc(text)}</span>`;
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

    function renderNodeTabs() {
      const tabs = $("nodeTabs");
      const empty = $("nodeEmpty");
      if (!state.nodes.length) {
        tabs.innerHTML = "";
        empty.hidden = false;
        return;
      }
      empty.hidden = true;
      tabs.innerHTML = state.nodes.map((node) => {
        const live = node.live || {};
        const dot = live.online ? "ok" : "bad";
        const label = node.name || node.ip;
        return `
          <button class="node-tab ${node.id === state.selectedId ? "active" : ""}" data-node-tab="${esc(node.id)}">
            <span class="node-tab-title"><span class="node-dot ${dot}"></span>${esc(label)}</span>
            <span class="node-tab-meta">${esc(node.ip)} · ${esc(live.service || "unknown")}</span>
          </button>
        `;
      }).join("");
      tabs.querySelectorAll("[data-node-tab]").forEach((btn) => {
        btn.addEventListener("click", () => selectNode(btn.dataset.nodeTab));
      });
    }

    function renderNodes() {
      const body = $("nodesBody");
      if (!state.nodes.length) {
        body.innerHTML = `<tr><td colspan="6" class="muted">No nodes yet</td></tr>`;
        return;
      }
      body.innerHTML = state.nodes.map((node) => {
        const live = node.live || {};
        const online = live.online ? pill("online", "ok") : pill("offline", "bad");
        const serviceKind = live.service === "active" ? "ok" : live.service === "unknown" ? "warn" : "bad";
        const service = pill(live.service || "unknown", serviceKind);
        const auth = live.auth_ok === true
          ? pill("ssh ok", "ok")
          : live.auth_ok === false
            ? pill("ssh fail", "bad")
            : (live.ssh_open ? pill("ssh open", "warn") : pill("no ssh", "bad"));
        return `
          <tr class="${node.id === state.selectedId ? "selected" : ""}" data-id="${esc(node.id)}">
            <td><strong>${esc(node.name)}</strong><div class="muted">${esc(live.hostname || "")}</div></td>
            <td>${esc(node.ip)}</td>
            <td>${online}<div class="muted">telnet ${live.telnet_open ? "open" : "closed"}</div></td>
            <td>${service}</td>
            <td>${auth}<div class="muted">${esc(live.auth_error || "")}</div></td>
            <td>
              <div class="toolbar">
                <button data-select="${esc(node.id)}">Focus</button>
                <button data-delete="${esc(node.id)}">Delete</button>
              </div>
            </td>
          </tr>
        `;
      }).join("");
      body.querySelectorAll("[data-select]").forEach((btn) => {
        btn.addEventListener("click", () => selectNode(btn.dataset.select));
      });
      body.querySelectorAll("[data-delete]").forEach((btn) => {
        btn.addEventListener("click", () => deleteNode(btn.dataset.delete));
      });
      body.querySelectorAll("tr[data-id]").forEach((row) => {
        row.addEventListener("dblclick", () => selectNode(row.dataset.id));
      });
    }

    function renderSelected() {
      const node = state.nodes.find((item) => item.id === state.selectedId);
      $("selectedNode").innerHTML = node
        ? `<strong>${esc(node.name)}</strong> <span class="muted">${esc(node.ip)} / ${esc(node.service)}</span>`
        : "No node selected";
      renderNodeTabs();
      renderNodes();
    }

    function selectNode(id) {
      if (state.selectedId && state.selectedId !== id) stopLogTail(false);
      state.selectedId = id;
      renderSelected();
    }

    async function loadConfig() {
      const data = await api("/api/config");
      $("scanCidr").value = data.default_cidr;
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
        $("scanState").textContent = `found: ${(data.discoveries || []).length}`;
        await loadNodes();
      } catch (err) {
        $("scanState").textContent = err.message;
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
            service: $("addService").value
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
      $("actionState").textContent = `${action}...`;
      try {
        const data = await api(`/api/nodes/${encodeURIComponent(node.id)}/action`, {
          method: "POST",
          body: { action }
        });
        const result = data.result || {};
        $("actionState").textContent = result.ok ? "done" : `error rc=${result.rc}`;
        writeOutput(`$ systemctl ${action} ${node.service}\n${result.stdout || ""}${result.stderr || ""}\n`);
        await loadNodes();
      } catch (err) {
        $("actionState").textContent = err.message;
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
