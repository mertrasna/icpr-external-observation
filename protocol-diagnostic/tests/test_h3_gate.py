from __future__ import annotations

import sys
import json
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path


DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

try:
    import h3_gate
except ModuleNotFoundError:
    h3_gate = None


class H3GatePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(h3_gate, "H3 origin-gate policy module is required")
        self.policy = h3_gate.GatePolicy(private_ipv4="10.0.0.10")
        self.session_id = "20260804T100000Z-a1b2c3d4"

    def valid_status(self, **changes: object):
        table_name = "icpr_h3req_20260804T100000Z_a1b2c3d4"
        status = h3_gate.GateStatus(
            session_id=self.session_id,
            table_name=table_name,
            table_count=1,
            chain_count=1,
            set_count=1,
            counter_count=1,
            rule_count=1,
            chain_priority=-10,
            chain_policy="accept",
            target_present=True,
            target_ipv4=self.policy.private_ipv4,
            remaining_seconds=900,
            packets=2,
            bytes=120,
            timer_active=True,
            timer_unit=f"icpr-h3req-rollback-{self.session_id}.timer",
            caddy_active=True,
            capture_active=True,
            exact_rule=(
                "ip daddr @blocked_targets tcp dport 443 "
                "counter name tcp443_dropped drop"
            ),
        )
        return replace(status, **changes)

    def test_rendered_batch_has_only_private_origin_tcp443_scope(self) -> None:
        batch = h3_gate.render_nft_batch(self.policy, self.session_id)

        self.assertIn("10.0.0.10 timeout 1800s", batch)
        self.assertIn("ip daddr @blocked_targets tcp dport 443", batch)
        self.assertIn("hook input priority -10; policy accept", batch)
        self.assertNotIn("udp dport", batch)
        self.assertNotIn("tcp dport 22", batch)
        self.assertNotIn("0.0.0.0/0", batch)

    def test_gate_status_rejects_less_than_slot_safety_margin(self) -> None:
        with self.assertRaises(h3_gate.GateError):
            h3_gate.validate_gate_status(
                self.valid_status(remaining_seconds=179), self.policy, 180
            )

    def test_gate_status_rejects_rule_without_destination_set(self) -> None:
        with self.assertRaises(h3_gate.GateError):
            h3_gate.validate_gate_status(
                self.valid_status(exact_rule="tcp dport 443 drop"),
                self.policy,
                180,
            )

    def test_gate_status_rejects_timer_for_another_session(self) -> None:
        with self.assertRaises(h3_gate.GateError):
            h3_gate.validate_gate_status(
                self.valid_status(timer_unit="icpr-h3req-rollback-other.timer"),
                self.policy,
                180,
            )

    def test_exact_gate_status_is_accepted(self) -> None:
        status = self.valid_status()

        validated = h3_gate.validate_gate_status(status, self.policy, 180)

        self.assertEqual(validated, status)

    def test_status_parser_rejects_missing_counter_evidence(self) -> None:
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
            "target_ipv4": self.policy.private_ipv4,
            "remaining_seconds": 900,
            "packets": 2,
            "timer_active": True,
            "timer_unit": f"icpr-h3req-rollback-{self.session_id}.timer",
            "caddy_active": True,
            "capture_active": True,
            "exact_rule": (
                "ip daddr @blocked_targets tcp dport 443 "
                "counter name tcp443_dropped drop"
            ),
        }

        with self.assertRaises(h3_gate.GateError):
            h3_gate.parse_gate_status(json.dumps(value))

    def test_remote_helper_rejects_malformed_session_before_privilege_use(self) -> None:
        helper = DIAGNOSTIC_ROOT.parent / "server" / "h3-required" / "icpr-h3-origin-gate"
        self.assertTrue(helper.is_file(), "server origin-gate helper is absent")

        completed = subprocess.run(
            [str(helper), "validate", "../unsafe", "10.0.0.10"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        value = json.loads(completed.stdout)
        self.assertEqual(value["status"], "error")
        self.assertEqual(value["error_code"], "invalid_session_id")

    def test_remote_helper_requires_one_canonical_private_ipv4(self) -> None:
        helper = DIAGNOSTIC_ROOT.parent / "server" / "h3-required" / "icpr-h3-origin-gate"
        session_id = self.session_id
        cases = (
            ([str(helper), "validate", session_id], "usage"),
            ([str(helper), "validate", session_id, "not-an-ip"], "invalid_origin_ipv4"),
            ([str(helper), "validate", session_id, "010.0.0.10"], "invalid_origin_ipv4"),
            ([str(helper), "validate", session_id, "10.0.0.999"], "invalid_origin_ipv4"),
            ([str(helper), "validate", session_id, "8.8.8.8"], "invalid_origin_ipv4"),
        )

        for argv, error_code in cases:
            with self.subTest(argv=argv):
                completed = subprocess.run(
                    argv,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                value = json.loads(completed.stdout)
                self.assertEqual(value["status"], "error")
                self.assertEqual(value["error_code"], error_code)


if __name__ == "__main__":
    unittest.main()
