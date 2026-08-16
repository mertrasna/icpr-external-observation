from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

import pairing
from icprlib import sha256_file, write_json, write_sidecar


class H3RequiredClassificationTests(unittest.TestCase):
    server_private_ipv4 = "10.0.0.10"

    def classify(self, *, condition: str, proto: str = "HTTP/3.0", **changes: object):
        values = {
            "condition": condition,
            "caddy_row": {"request": {"proto": proto}},
            "server_flow": {"fresh": True, "transport": "udp_quic_initial"},
            "client": {
                "direct_origin_contacts": [],
                "alternative_udp_failover": False,
                "unambiguous_tcp_fallback": condition == "udp_blocked",
                "outer_transport": "tcp" if condition == "udp_blocked" else "udp",
            },
            "pf": {"valid": True, "enforced": condition == "udp_blocked", "delta": 1},
            "egress_catalogue_match": True,
            "real_ip_match": False,
            "pairing_errors": [],
            "integrity_errors": [],
            "origin_gate_valid": True,
        }
        values.update(changes)
        self.assertTrue(hasattr(pairing, "classify_h3_required_trial"))
        return pairing.classify_h3_required_trial(**values)

    def test_permitted_h3_supports_required_destination_capability(self) -> None:
        result = self.classify(condition="udp_permitted")
        self.assertEqual(result[0], "destination_h3_required")

    def test_permitted_h3_without_attributable_outer_udp_is_not_supporting(self) -> None:
        result = self.classify(
            condition="udp_permitted",
            client={
                "direct_origin_contacts": [],
                "alternative_udp_failover": False,
                "unambiguous_tcp_fallback": False,
                "outer_transport": "tcp",
            },
        )
        self.assertEqual(
            result[:2],
            ("permitted_without_attributable_outer_udp", "observed_non_supporting"),
        )

    def test_blocked_h3_with_pf_and_outer_tcp_supports_strong_claim(self) -> None:
        result = self.classify(condition="udp_blocked")
        self.assertEqual(result[0], "outer_tcp_fallback_destination_h3_required")

    def test_http2_under_valid_origin_gate_is_integrity_contradiction(self) -> None:
        result = self.classify(condition="udp_permitted", proto="HTTP/2.0")
        self.assertEqual(result[:2], ("origin_gate_protocol_contradiction", "excluded_ambiguous"))

    def test_zero_blocked_pf_delta_is_unevaluable(self) -> None:
        result = self.classify(
            condition="udp_blocked",
            pf={"valid": True, "enforced": False, "delta": 0},
        )
        self.assertEqual(result[0], "blocked_gate_not_engaged")

    def test_missing_origin_gate_evidence_is_excluded(self) -> None:
        result = self.classify(condition="udp_permitted", origin_gate_valid=False)
        self.assertEqual(result[:2], ("origin_gate_integrity_failure", "excluded_ambiguous"))

    def test_gate_evidence_requires_same_session_and_positive_lifetime(self) -> None:
        session_id = "20260804T100000Z-a1b2c3d4"
        status = {
            "session_id": session_id,
            "table_name": "icpr_h3req_20260804T100000Z_a1b2c3d4",
            "table_count": 1,
            "chain_count": 1,
            "set_count": 1,
            "counter_count": 1,
            "rule_count": 1,
            "chain_priority": -10,
            "chain_policy": "accept",
            "target_present": True,
            "target_ipv4": self.server_private_ipv4,
            "remaining_seconds": 300,
            "timer_active": True,
            "timer_unit": "icpr-h3req-rollback-20260804T100000Z-a1b2c3d4.timer",
            "caddy_active": True,
            "capture_active": True,
            "exact_rule": "ip daddr @blocked_targets tcp dport 443 counter name tcp443_dropped drop",
        }
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            for name in ("origin-gate-pre.json", "origin-gate-post.json"):
                write_json(attempt / name, status)
                write_sidecar(attempt / name)
            metadata = {
                "gate_session_id": session_id,
                "origin_gate_pre_sha256": sha256_file(attempt / "origin-gate-pre.json"),
            }

            result = pairing.validate_origin_gate_evidence(
                attempt, metadata, self.server_private_ipv4
            )

        self.assertTrue(result["valid"])

    def test_gate_evidence_rejects_nonunique_rule_shape(self) -> None:
        session_id = "20260804T100000Z-a1b2c3d4"
        status = {
            "session_id": session_id,
            "table_name": "icpr_h3req_20260804T100000Z_a1b2c3d4",
            "table_count": 1,
            "chain_count": 1,
            "set_count": 1,
            "counter_count": 1,
            "rule_count": 2,
            "chain_priority": -10,
            "chain_policy": "accept",
            "target_present": True,
            "target_ipv4": self.server_private_ipv4,
            "remaining_seconds": 300,
            "timer_active": True,
            "timer_unit": "icpr-h3req-rollback-20260804T100000Z-a1b2c3d4.timer",
            "caddy_active": True,
            "capture_active": True,
            "exact_rule": "ip daddr @blocked_targets tcp dport 443 counter name tcp443_dropped drop",
        }
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            for name in ("origin-gate-pre.json", "origin-gate-post.json"):
                write_json(attempt / name, status)
                write_sidecar(attempt / name)
            metadata = {
                "gate_session_id": session_id,
                "origin_gate_pre_sha256": sha256_file(attempt / "origin-gate-pre.json"),
            }
            with self.assertRaises(pairing.PairingError):
                pairing.validate_origin_gate_evidence(
                    attempt, metadata, self.server_private_ipv4
                )

    def test_gate_evidence_rejects_target_from_another_configuration(self) -> None:
        session_id = "20260804T100000Z-a1b2c3d4"
        status = {
            "session_id": session_id,
            "table_name": "icpr_h3req_20260804T100000Z_a1b2c3d4",
            "table_count": 1,
            "chain_count": 1,
            "set_count": 1,
            "counter_count": 1,
            "rule_count": 1,
            "chain_priority": -10,
            "chain_policy": "accept",
            "target_present": True,
            "target_ipv4": "10.0.0.11",
            "remaining_seconds": 300,
            "timer_active": True,
            "timer_unit": f"icpr-h3req-rollback-{session_id}.timer",
            "caddy_active": True,
            "capture_active": True,
            "exact_rule": "ip daddr @blocked_targets tcp dport 443 counter name tcp443_dropped drop",
        }
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            for name in ("origin-gate-pre.json", "origin-gate-post.json"):
                write_json(attempt / name, status)
                write_sidecar(attempt / name)
            metadata = {
                "gate_session_id": session_id,
                "origin_gate_pre_sha256": sha256_file(
                    attempt / "origin-gate-pre.json"
                ),
            }

            with self.assertRaises(pairing.PairingError):
                pairing.validate_origin_gate_evidence(
                    attempt, metadata, self.server_private_ipv4
                )

    def test_denominator_requires_all_five_permitted_and_five_blocked_slots(self) -> None:
        results = []
        for index in range(1, 11):
            results.append(
                {
                    "slot_id": f"h3-required-v1-{index:03d}",
                    "retry_number": 1,
                    "condition": "udp_permitted" if index % 2 else "udp_blocked",
                    "classification": "observed",
                    "acceptance": "observed_non_supporting",
                }
            )
        self.assertTrue(hasattr(pairing, "summarize_h3_required"))

        complete = pairing.summarize_h3_required(results)
        incomplete = pairing.summarize_h3_required(results[:-1])

        self.assertTrue(complete["final_complete"])
        self.assertFalse(incomplete["final_complete"])
        self.assertEqual(complete["planned_slots"], {"udp_permitted": 5, "udp_blocked": 5})

        results[-1]["condition"] = "udp_permitted"
        wrong_balance = pairing.summarize_h3_required(results)
        self.assertFalse(wrong_balance["final_complete"])


if __name__ == "__main__":
    unittest.main()
