from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

import icprlib  # noqa: E402
from objective_eligibility import (  # noqa: E402
    eligibility_for_record,
    write_objective_eligibility,
)


def valid_record() -> dict:
    return {
        "run_id": "icpr-test",
        "campaign": "campaign-test",
        "client_start_utc": "2026-07-25T08:00:00Z",
        "server_time_utc": "2026-07-25T08:00:02Z",
        "run_mode": "campaign",
        "session": "morning",
        "slot_id": "test-slot",
        "block_id": "unpinned-mgl",
        "intended_ingress_group": "unpinned",
        "private_relay_state": "on",
        "disposition": "accepted",
        "exclusion_reason": "",
        "pending_reason": "",
        "triggered_exclusions": [],
        "client_outcome": "success",
        "condition_changed": False,
        "server_delivery_count": 1,
        "response_status": 200,
        "server_remote_ip": "198.51.100.20",
        "server_remote_port": 44321,
        "server_transport": "tcp",
        "server_http_protocol": "HTTP/2.0",
        "server_flow_key": "tcp|198.51.100.20|44321|10.0.0.10|443",
        "request_uuid": "uuid-test",
        "freshness_evidence": {"kind": "tcp_syn", "frame_numbers": [1]},
        "protocol_classification": "tcp_downgrade",
        "observed_ingress_ip": "203.0.113.10",
        "ingress_transport": "udp",
        "ingress_5tuple": "udp|192.0.2.2|50000|203.0.113.10|443",
        "client_ingress_candidates": [{"ingress_ip": "203.0.113.10"}],
        "ingress_asn": "64510",
        "egress_asn": "64520",
        "ingress_operator": "operator-a",
        "egress_operator": "operator-a",
        "same_operator": True,
        "apple_feed_date": "2026-07-25",
        "apple_feed_hash": "a" * 64,
        "apple_feed_match": {
            "ip_prefix": "198.51.100.0/24",
            "country": "ZZ",
            "region": "EXAMPLE",
            "city": "Example City",
        },
        "matched_prefix": "198.51.100.0/24",
        "advertised_country": "ZZ",
        "advertised_region": "EXAMPLE",
        "advertised_city": "Example City",
        "disclosure_class": "city_level_consistent",
        "pin_contact_status": "not_applicable",
    }


class ObjectiveEligibilityTests(unittest.TestCase):
    def test_e04_preserves_destination_and_location_but_blocks_exact_ingress(self) -> None:
        record = valid_record()
        record.update(
            disposition="excluded",
            exclusion_reason="E04_WRONG_OR_UNKNOWN_INGRESS",
            triggered_exclusions=["E04_WRONG_OR_UNKNOWN_INGRESS"],
            observed_ingress_ip="",
            ingress_transport="",
            ingress_5tuple="",
            ingress_asn="",
            ingress_operator="",
            same_operator="",
        )
        original = dict(record)

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertEqual(result["objective_1_destination_result"], "http2_delivered")
        self.assertFalse(result["objective_1_outer_leg_eligible"])
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertTrue(result["objective_3_location_eligible"])
        self.assertTrue(result["objective_3_primary_eligible"])
        self.assertEqual(result["strict_disposition"], "excluded")
        self.assertEqual(
            result["strict_exclusion_reason"], "E04_WRONG_OR_UNKNOWN_INGRESS"
        )
        self.assertEqual(record, original)

    def test_missing_asn_mapping_does_not_block_destination_or_location(self) -> None:
        record = valid_record()
        record.update(
            disposition="pending",
            pending_reason="dated_asn_mapping_missing",
            ingress_asn="",
            egress_asn="",
            ingress_operator="",
            egress_operator="",
            same_operator="",
        )

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertEqual(result["objective_1_destination_result"], "http2_delivered")
        self.assertTrue(result["objective_1_outer_leg_eligible"])
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertTrue(result["objective_3_location_eligible"])

    def test_concurrent_established_ingress_blocks_only_exact_pair(self) -> None:
        record = valid_record()
        record["client_ingress_candidates"] = [
            {"ingress_ip": record["observed_ingress_ip"]},
            {"ingress_ip": "203.0.113.11"},
        ]

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertTrue(result["objective_1_outer_leg_eligible"])
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertIn(
            "ambiguous_attribution_ingress_contact",
            result["objective_2_exact_pair_reason"],
        )
        self.assertTrue(result["objective_3_location_eligible"])

    def test_exact_pair_accepts_repeated_contacts_to_selected_ingress(self) -> None:
        record = valid_record()
        record["client_ingress_candidates"] = json.dumps(
            [
                {"ingress_ip": record["observed_ingress_ip"]},
                {"ingress_ip": record["observed_ingress_ip"]},
            ]
        )

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_2_exact_pair_eligible"])

    def test_corrupt_evidence_blocks_every_objective(self) -> None:
        record = valid_record()
        record.update(
            disposition="excluded",
            exclusion_reason="E07_CLOCK_OR_LOG_CORRUPTION",
            triggered_exclusions=["E07_CLOCK_OR_LOG_CORRUPTION"],
        )

        result = eligibility_for_record(record)

        self.assertFalse(result["objective_1_destination_eligible"])
        self.assertFalse(result["objective_1_outer_leg_eligible"])
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertFalse(result["objective_3_location_eligible"])

    def test_location_requires_same_day_apple_feed_match(self) -> None:
        record = valid_record()
        record.update(
            apple_feed_date="",
            apple_feed_hash="",
            apple_feed_match={},
            matched_prefix="",
            advertised_country="",
            disclosure_class="",
        )

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertFalse(result["objective_3_location_eligible"])

    def test_real_ip_bypass_keeps_explicit_destination_result(self) -> None:
        record = valid_record()
        record.update(
            disposition="excluded",
            exclusion_reason="E05_REAL_IP_AT_DESTINATION",
            triggered_exclusions=["E05_REAL_IP_AT_DESTINATION"],
        )

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertEqual(
            result["objective_1_destination_result"],
            "real_ip_bypass_http2",
        )
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertFalse(result["objective_3_location_eligible"])

    def test_non_feed_delivery_keeps_explicit_destination_result(self) -> None:
        record = valid_record()
        record.update(
            disposition="excluded",
            exclusion_reason="E06_EGRESS_NOT_IN_FEED",
            triggered_exclusions=["E06_EGRESS_NOT_IN_FEED"],
            apple_feed_match={},
            matched_prefix="",
            advertised_country="",
            disclosure_class="",
        )

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_1_destination_eligible"])
        self.assertEqual(
            result["objective_1_destination_result"],
            "non_feed_http2",
        )
        self.assertFalse(result["objective_2_exact_pair_eligible"])
        self.assertFalse(result["objective_3_location_eligible"])

    def test_pinned_location_is_supporting_not_primary(self) -> None:
        record = valid_record()
        record["intended_ingress_group"] = "apple_as714"

        result = eligibility_for_record(record)

        self.assertTrue(result["objective_3_location_eligible"])
        self.assertFalse(result["objective_3_primary_eligible"])
        self.assertEqual(result["objective_3_analysis_role"], "supporting_pinned")

    def test_writer_hashes_csv_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outputs = write_objective_eligibility(
                [valid_record()], Path(temporary) / "derived"
            )
            with outputs["objective_eligibility"].open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            summary = json.loads(
                outputs["objective_eligibility_summary"].read_text(encoding="utf-8")
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["strict_disposition"], "accepted")
            self.assertTrue(summary["strict_dispositions_are_unchanged"])
            self.assertEqual(
                summary["objective_1_destination_result_counts"],
                {"http2_delivered": 1},
            )
            self.assertEqual(
                icprlib.verify_sidecar(outputs["objective_eligibility"]),
                icprlib.sha256_file(outputs["objective_eligibility"]),
            )
            self.assertEqual(
                icprlib.verify_sidecar(outputs["objective_eligibility_summary"]),
                icprlib.sha256_file(outputs["objective_eligibility_summary"]),
            )


if __name__ == "__main__":
    unittest.main()
