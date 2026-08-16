from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

try:
    import server_gate
except ModuleNotFoundError:
    server_gate = None
import h3_gate
import protocol_diag


class RecordingRunner:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")


class ServerGateClientTests(unittest.TestCase):
    session_id = "20260804T100000Z-a1b2c3d4"
    private_ipv4 = "10.0.0.10"
    ssh_target = "researcher@gate.example.org"

    def setUp(self) -> None:
        self.assertIsNotNone(server_gate, "server gate client module is required")

    def status_json(self, **changes: object) -> str:
        value = {
            "session_id": self.session_id,
            "table_name": "icpr_h3req_20260804T100000Z_a1b2c3d4",
            "table_count": 1,
            "chain_count": 1,
            "set_count": 1,
            "counter_count": 1,
            "rule_count": 1,
            "chain_priority": -10,
            "chain_policy": "accept",
            "target_present": True,
            "target_ipv4": self.private_ipv4,
            "remaining_seconds": 900,
            "packets": 2,
            "bytes": 120,
            "timer_active": True,
            "timer_unit": f"icpr-h3req-rollback-{self.session_id}.timer",
            "caddy_active": True,
            "capture_active": True,
            "exact_rule": (
                "ip daddr @blocked_targets tcp dport 443 "
                "counter name tcp443_dropped drop"
            ),
        }
        value.update(changes)
        return json.dumps(value)

    def test_snapshot_uses_fixed_ssh_argv_and_revalidates_status(self) -> None:
        runner = RecordingRunner(self.status_json())
        client = server_gate.ServerGateClient(
            host=self.ssh_target,
            key_path=Path("/tmp/icpr-test-key"),
            helper_path="/usr/local/sbin/icpr-h3-origin-gate",
            policy=h3_gate.GatePolicy(private_ipv4=self.private_ipv4),
            runner=runner,
        )

        result = client.snapshot(self.session_id)

        self.assertEqual(result["session_id"], self.session_id)
        self.assertEqual(
            runner.calls,
            [[
                "/usr/bin/ssh",
                "-i",
                str(Path("/tmp/icpr-test-key").resolve()),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                self.ssh_target,
                "sudo",
                "--non-interactive",
                "/usr/local/sbin/icpr-h3-origin-gate",
                "status",
                self.session_id,
                self.private_ipv4,
            ]],
        )

    def test_snapshot_rejects_status_below_slot_margin(self) -> None:
        runner = RecordingRunner(self.status_json(remaining_seconds=179))
        client = server_gate.ServerGateClient(
            host=self.ssh_target,
            key_path=Path("/tmp/icpr-test-key"),
            helper_path="/usr/local/sbin/icpr-h3-origin-gate",
            policy=h3_gate.GatePolicy(private_ipv4=self.private_ipv4),
            runner=runner,
        )

        with self.assertRaises(server_gate.ServerGateError):
            client.snapshot(self.session_id)

    def test_malformed_session_is_rejected_before_ssh(self) -> None:
        runner = RecordingRunner(self.status_json())
        client = server_gate.ServerGateClient(
            host=self.ssh_target,
            key_path=Path("/tmp/icpr-test-key"),
            helper_path="/usr/local/sbin/icpr-h3-origin-gate",
            policy=h3_gate.GatePolicy(private_ipv4=self.private_ipv4),
            runner=runner,
        )

        with self.assertRaises(server_gate.ServerGateError):
            client.snapshot("../unsafe")
        self.assertEqual(runner.calls, [])

    def test_validate_requires_successful_session_bound_remote_json(self) -> None:
        runner = RecordingRunner(
            json.dumps(
                {
                    "status": "validated",
                    "session_id": self.session_id,
                    "table_name": "icpr_h3req_20260804T100000Z_a1b2c3d4",
                    "nft_batch_sha256": "a" * 64,
                    "mutated": False,
                }
            )
        )
        client = server_gate.ServerGateClient(
            host=self.ssh_target,
            key_path=Path("/tmp/icpr-test-key"),
            helper_path="/usr/local/sbin/icpr-h3-origin-gate",
            policy=h3_gate.GatePolicy(private_ipv4=self.private_ipv4),
            runner=runner,
        )

        result = client.validate(self.session_id)

        self.assertEqual(result["status"], "validated")
        self.assertEqual(
            runner.calls[0][-3:],
            ["validate", self.session_id, self.private_ipv4],
        )

    def test_remote_failure_never_returns_gate_evidence(self) -> None:
        runner = RecordingRunner(
            json.dumps({"status": "error", "error_code": "stale_gate"}),
            returncode=2,
        )
        client = server_gate.ServerGateClient(
            host=self.ssh_target,
            key_path=Path("/tmp/icpr-test-key"),
            helper_path="/usr/local/sbin/icpr-h3-origin-gate",
            policy=h3_gate.GatePolicy(private_ipv4=self.private_ipv4),
            runner=runner,
        )

        with self.assertRaises(server_gate.ServerGateError):
            client.validate(self.session_id)


class GateCommandParserTests(unittest.TestCase):
    def test_controller_exposes_four_explicit_gate_commands(self) -> None:
        parser = protocol_diag.parser("h3_required")
        commands = {
            action.dest: action.choices
            for action in parser._actions
            if getattr(action, "choices", None)
        }
        available = commands["command"]

        self.assertIn("gate-validate", available)
        self.assertIn("gate-arm", available)
        self.assertIn("gate-status", available)
        self.assertIn("gate-disarm", available)

    def test_h3_slots_require_gate_session_while_legacy_slots_do_not(self) -> None:
        self.assertTrue(hasattr(protocol_diag, "validate_gate_session_request"))
        self.assertIsNone(
            protocol_diag.validate_gate_session_request("dual_protocol", None)
        )
        with self.assertRaises(Exception):
            protocol_diag.validate_gate_session_request("h3_required", None)
        self.assertEqual(
            protocol_diag.validate_gate_session_request(
                "h3_required", "20260804T100000Z-a1b2c3d4"
            ),
            "20260804T100000Z-a1b2c3d4",
        )


if __name__ == "__main__":
    unittest.main()
