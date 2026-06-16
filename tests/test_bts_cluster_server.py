from __future__ import annotations

import json
import subprocess
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

    def test_telnet_error_message_explains_connection_refused(self) -> None:
        message = server.telnet_error_message(
            ConnectionRefusedError(111, "Connection refused"),
            "192.168.1.20",
            5038,
        )
        self.assertIn("Telnet connection refused by 192.168.1.20:5038", message)
        self.assertIn("Yate rmanager is not listening", message)

    def test_telnet_error_message_explains_timeout(self) -> None:
        message = server.telnet_error_message(
            TimeoutError(110, "Connection timed out"),
            "192.168.1.20",
            5038,
        )
        self.assertIn("timed out", message)
        self.assertIn("192.168.1.20:5038", message)

    def test_parse_service_status_uses_main_pid_fallback(self) -> None:
        parsed = server.parse_service_status_stdout(
            "hostname=pi-bts\n"
            "service=unknown\n"
            "active_state=\n"
            "substate=\n"
            "main_pid=1234\n"
            "yate_pid=\n"
        )
        self.assertEqual(parsed["hostname"], "pi-bts")
        self.assertEqual(parsed["service"], "active")

    def test_parse_service_status_uses_yate_process_fallback(self) -> None:
        parsed = server.parse_service_status_stdout(
            "hostname=pi-bts\n"
            "service=inactive\n"
            "active_state=inactive\n"
            "substate=dead\n"
            "main_pid=0\n"
            "yate_pid=4321\n"
        )
        self.assertEqual(parsed["service"], "active")

    def test_parse_service_status_uses_yate_command_fallback(self) -> None:
        parsed = server.parse_service_status_stdout(
            "hostname=pi-bts\n"
            "service=unknown\n"
            "active_state=unknown\n"
            "substate=dead\n"
            "main_pid=0\n"
            "yate_pid=\n"
            "yate_cmd_pid=9876\n"
        )
        self.assertEqual(parsed["service"], "active")

    def test_validate_node_uniqueness_rejects_duplicate_ip(self) -> None:
        existing = server.Node(id="n1", name="bts-1", ip="192.168.1.10")
        candidate = server.Node(id="n2", name="bts-2", ip="192.168.1.10")

        with self.assertRaises(ValueError):
            server.validate_node_uniqueness([existing], candidate)

    def test_validate_node_uniqueness_rejects_duplicate_frequency(self) -> None:
        existing = server.Node(id="n1", name="bts-1", ip="192.168.1.10", radio_band="900", radio_c0="975")
        candidate = server.Node(id="n2", name="bts-2", ip="192.168.1.11", radio_band="900", radio_c0="975")

        with self.assertRaises(ValueError):
            server.validate_node_uniqueness([existing], candidate)

    def test_validate_node_uniqueness_allows_different_arfcn(self) -> None:
        existing = server.Node(id="n1", name="bts-1", ip="192.168.1.10", radio_band="900", radio_c0="975")
        candidate = server.Node(id="n2", name="bts-2", ip="192.168.1.11", radio_band="900", radio_c0="976")

        server.validate_node_uniqueness([existing], candidate)

    def test_ms_ip_range_uses_base_and_max_count(self) -> None:
        node = server.Node(
            id="n1",
            name="bts-1",
            ip="192.168.1.10",
            ms_ip_base="192.168.99.1",
            ms_ip_max_count="254",
        )

        self.assertEqual(
            server.ms_ip_range(node),
            (int(server.ipaddress.IPv4Address("192.168.99.1")), int(server.ipaddress.IPv4Address("192.168.99.254"))),
        )

    def test_validate_node_uniqueness_rejects_overlapping_ms_ip_ranges(self) -> None:
        existing = server.Node(
            id="n1",
            name="bts-1",
            ip="192.168.1.10",
            ms_ip_base="192.168.99.1",
            ms_ip_max_count="100",
        )
        candidate = server.Node(
            id="n2",
            name="bts-2",
            ip="192.168.1.11",
            ms_ip_base="192.168.99.50",
            ms_ip_max_count="100",
        )

        with self.assertRaises(ValueError):
            server.validate_node_uniqueness([existing], candidate)

    def test_validate_node_uniqueness_allows_adjacent_ms_ip_ranges(self) -> None:
        existing = server.Node(
            id="n1",
            name="bts-1",
            ip="192.168.1.10",
            ms_ip_base="192.168.99.1",
            ms_ip_max_count="100",
        )
        candidate = server.Node(
            id="n2",
            name="bts-2",
            ip="192.168.1.11",
            ms_ip_base="192.168.99.101",
            ms_ip_max_count="100",
        )

        server.validate_node_uniqueness([existing], candidate)


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

    def test_rmanager_addr_update_changes_only_general_addr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "rmanager.conf"
            conf.write_text(
                "[general]\n"
                ";port=5038\n"
                ";addr=127.0.0.1\n"
                "telnet=yes\n"
                "\n"
                "[other]\n"
                "addr=10.1.1.1\n"
            )
            subprocess.run(
                ["python3", "-c", server.rmanager_addr_update_script(), str(conf), "0.0.0.0"],
                check=True,
            )
            updated = conf.read_text()

        self.assertIn(";port=5038", updated)
        self.assertIn("addr=0.0.0.0", updated)
        self.assertIn("[other]\naddr=10.1.1.1", updated)
        self.assertNotIn(";addr=127.0.0.1", updated)


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

    def test_probe_node_treats_open_telnet_as_active_when_systemctl_unknown(self) -> None:
        node = server.Node(id="n1", name="bts", ip="192.168.1.10")
        tcp_results = [True, True]
        ssh_result = {"ok": True, "stdout": "", "stderr": "", "rc": 0}
        with (
            patch.object(server, "tcp_open", side_effect=tcp_results),
            patch.object(
                server,
                "service_status",
                return_value={"hostname": "pi-bts", "service": "unknown", "ssh": ssh_result},
            ),
        ):
            info = server.probe_node(node)

        self.assertEqual(info["service"], "active")


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
