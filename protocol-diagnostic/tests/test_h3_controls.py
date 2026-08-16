from __future__ import annotations

import sys
import unittest
from pathlib import Path


DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

try:
    import h3_controls
except ModuleNotFoundError:
    h3_controls = None
import protocol_diag


class H3ControlGateTests(unittest.TestCase):
    session_id = "20260804T100000Z-a1b2c3d4"

    def setUp(self) -> None:
        self.assertIsNotNone(h3_controls, "H3 control validator is required")

    def valid_controls(self) -> dict[str, dict[str, object]]:
        return {
            "warmup": {
                "status": "verified",
                "counted": False,
                "private_relay_state": "off",
                "alt_svc_h3": True,
                "safari_healthz_opened": True,
                "safari_fully_quit_after": True,
            },
            "tcp_control": {
                "status": "verified",
                "counted": False,
                "gate_session_id": self.session_id,
                "tcp_connect_succeeded": False,
                "source_ipv4": "198.51.100.42",
                "gate_counter_delta": 1,
                "matching_server_tcp_syn": True,
            },
            "pre_h3_control": {
                "status": "verified",
                "counted": False,
                "gate_session_id": self.session_id,
                "private_relay_state": "off",
                "http_protocol": "HTTP/3.0",
                "remote_ip": "198.51.100.42",
                "expected_real_ip": "198.51.100.42",
                "fresh_server_quic_initial": True,
                "exactly_one_caddy_record": True,
            },
        }

    def test_exact_pre_series_controls_unlock_counted_slots(self) -> None:
        result = h3_controls.validate_controls_ready(
            self.valid_controls(), self.session_id
        )
        self.assertEqual(result["status"], "ready")

    def test_missing_pre_h3_control_keeps_series_blocked(self) -> None:
        controls = self.valid_controls()
        del controls["pre_h3_control"]
        with self.assertRaises(h3_controls.ControlError):
            h3_controls.validate_controls_ready(controls, self.session_id)

    def test_tcp_control_without_positive_gate_delta_is_rejected(self) -> None:
        controls = self.valid_controls()
        controls["tcp_control"]["gate_counter_delta"] = 0
        with self.assertRaises(h3_controls.ControlError):
            h3_controls.validate_controls_ready(controls, self.session_id)

    def test_controller_exposes_non_live_control_verification(self) -> None:
        parser = protocol_diag.parser("h3_required")
        action = next(
            item
            for item in parser._actions
            if item.dest == "command" and getattr(item, "choices", None)
        )
        self.assertIn("verify-controls", action.choices)


if __name__ == "__main__":
    unittest.main()
