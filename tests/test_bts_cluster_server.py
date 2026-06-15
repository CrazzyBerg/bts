from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bts_cluster.server as server


class ValidationTest(unittest.TestCase):
    def test_validate_log_path_accepts_absolute_path(self) -> None:
        self.assertEqual(server.validate_log_path("/var/log/yate.err"), "/var/log/yate.err")

    def test_validate_log_path_rejects_relative_path(self) -> None:
        with self.assertRaises(ValueError):
            server.validate_log_path("../yate.err")

    def test_validate_log_path_rejects_newline(self) -> None:
        with self.assertRaises(ValueError):
            server.validate_log_path("/var/log/yate.err\nwhoami")

    def test_normalize_tail_lines_clamps_range(self) -> None:
        self.assertEqual(server.normalize_tail_lines("-10"), 0)
        self.assertEqual(server.normalize_tail_lines("120"), 120)
        self.assertEqual(server.normalize_tail_lines("9999"), 2000)
        self.assertEqual(server.normalize_tail_lines("bad"), 200)


class CommandBuildTest(unittest.TestCase):
    def test_build_tail_command_quotes_path(self) -> None:
        node = server.Node(id="n1", name="bts", ip="192.168.1.10", password="")
        command = server.build_tail_command(node, "/var/log/yate err", 50, use_sudo=False)
        self.assertEqual(command, "tail -n 50 -F -- '/var/log/yate err'")

    def test_build_tail_command_uses_sudo_password_when_available(self) -> None:
        node = server.Node(id="n1", name="bts", ip="192.168.1.10", password="raspberry")
        command = server.build_tail_command(node, "/var/log/yate.err", 10, use_sudo=True)
        self.assertIn("sudo -S -p '' tail -n 10 -F -- /var/log/yate.err", command)
        self.assertIn("raspberry", command)


class InventoryTest(unittest.TestCase):
    def test_save_and_load_nodes_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            with patch.object(server, "DATA_DIR", Path(tmp)), patch.object(server, "INVENTORY_PATH", inventory):
                expected = [
                    server.Node(
                        id="node-1",
                        name="bts-1",
                        ip="192.168.1.10",
                        user="pi",
                        password="raspberry",
                    )
                ]
                server.save_nodes(expected)
                loaded = server.load_nodes()

        self.assertEqual(loaded, expected)

    def test_node_public_hides_password(self) -> None:
        node = server.Node(id="node-1", name="bts-1", ip="192.168.1.10", password="secret")
        public = server.node_public(node)
        self.assertNotIn("password", public)
        self.assertTrue(public["has_password"])


class ScanTest(unittest.TestCase):
    def test_scan_subnet_rejects_large_networks_before_connecting(self) -> None:
        with patch.object(server, "tcp_open") as tcp_open:
            with self.assertRaises(ValueError):
                server.scan_subnet("10.0.0.0/16")
        tcp_open.assert_not_called()


class HttpApiTest(unittest.TestCase):
    def test_create_node_api_saves_node_and_returns_public_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            app = object.__new__(server.App)
            captured: dict[str, object] = {}
            payload = {
                "name": "rack-1",
                "ip": "192.168.1.20",
                "user": "pi",
                "password": "raspberry",
                "service": "yate.service",
            }

            def capture_response(_handler: object, status: int, body: dict[str, object]) -> None:
                captured["status"] = status
                captured["body"] = body

            with (
                patch.object(server, "DATA_DIR", Path(tmp)),
                patch.object(server, "INVENTORY_PATH", inventory),
                patch.object(server, "probe_node", return_value={"online": False}),
                patch.object(server, "json_response", side_effect=capture_response),
            ):
                server.App.create_node(app, payload)
                stored = json.loads(inventory.read_text())

        self.assertEqual(captured["status"], server.HTTPStatus.OK)
        body = captured["body"]
        self.assertIsInstance(body, dict)
        node = body["node"]  # type: ignore[index]
        self.assertNotIn("password", node)
        self.assertEqual(node["ip"], "192.168.1.20")
        self.assertEqual(stored["nodes"][0]["password"], "raspberry")


if __name__ == "__main__":
    unittest.main()
