from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "pairing.py"
SPEC = importlib.util.spec_from_file_location("protocol_diagnostic_pairing", MODULE_PATH)
assert SPEC and SPEC.loader
pairing = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pairing
SPEC.loader.exec_module(pairing)


RUN_ID = "icprdiag-20260803T070000Z-0011223344556677"
EGRESS = "198.51.100.20"
REAL = "192.0.2.44"
INGRESS = "203.0.113.10"
ALT = "203.0.113.11"
ORIGIN = "203.0.113.200"
PRIVATE = "10.0.0.10"
NOW = dt.datetime(2026, 8, 3, 7, 0, tzinfo=dt.timezone.utc)


def caddy(proto: str = "HTTP/3.0") -> dict:
    return {
        "ts": NOW.timestamp() + 5,
        "run_id": RUN_ID,
        "request_uuid": "uuid-1",
        "request": {
            "remote_ip": EGRESS,
            "remote_port": "45678",
            "proto": proto,
            "method": "GET",
            "host": "measurement.example.org",
            "uri": f"/probe/{RUN_ID}",
        },
        "status": 200,
    }


def packet(**overrides):
    value = {
        "frame_number": 1,
        "time_epoch": NOW.timestamp() + 1,
        "src_ip": REAL,
        "dst_ip": INGRESS,
        "transport": "udp",
        "src_port": 55000,
        "dst_port": 443,
        "tcp_syn": False,
        "tcp_ack": False,
        "quic_initial": True,
        "quic_dcid": "aabb",
        "artifact": "fixture.pcap",
        "artifact_sha256": "a" * 64,
    }
    value.update(overrides)
    return value


class PairingHelpersTest(unittest.TestCase):
    def test_live_caddy_prefix_requires_bound_read_only_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix_root = root / "server/recovery-data/live-caddy-prefixes"
            caddy_path = prefix_root / "snapshot/access-prefix.jsonl"
            caddy_path.parent.mkdir(parents=True)
            caddy_path.write_text('{"run_id":"r"}\n', encoding="utf-8")
            artifact_hash = pairing.icprlib.sha256_file(caddy_path)
            pairing.icprlib.write_sidecar(caddy_path)
            provenance_path = caddy_path.parent / "snapshot-provenance.json"
            provenance = {
                "schema_version": 1,
                "document_type": "icpr_live_caddy_prefix_snapshot",
                "status": "verified",
                "capture_method": "nonselective_active_log_byte_prefix_v1",
                "source_nonselective_prefix": True,
                "source_mutated": False,
                "active_pcap_copied": False,
                "snapshot_path": str(caddy_path.relative_to(root)),
                "snapshot_sha256": artifact_hash,
                "prefix_bytes": caddy_path.stat().st_size,
                "source_stat_before": {"device": 1, "inode": 2, "size_bytes": 0},
                "source_stat_after": {
                    "device": 1,
                    "inode": 2,
                    "size_bytes": caddy_path.stat().st_size,
                },
            }
            pairing.icprlib.write_json(provenance_path, provenance)
            pairing.icprlib.write_sidecar(provenance_path)
            with (
                mock.patch.object(pairing, "REPO_ROOT", root),
                mock.patch.object(pairing, "LIVE_CADDY_PREFIX_ROOT", prefix_root),
            ):
                loaded = pairing.verify_live_caddy_prefix(caddy_path, artifact_hash)
            self.assertEqual(loaded["snapshot_sha256"], artifact_hash)

    def test_exact_pair_requires_uuid_and_five_tuple_match(self) -> None:
        metadata = {"run_id": RUN_ID}
        response = {
            "run_id": RUN_ID,
            "request_uuid": "uuid-1",
            "remote_ip": EGRESS,
            "remote_port": 45678,
            "http_protocol": "HTTP/3.0",
            "request_host": "measurement.example.org",
            "request_uri": f"/probe/{RUN_ID}",
            "server_unix_ms": int((NOW.timestamp() + 5) * 1000),
        }
        selected, errors = pairing.exact_caddy_pair([caddy()], metadata, response)
        self.assertIsNotNone(selected)
        self.assertEqual(errors, [])
        response["remote_port"] = 45679
        selected, errors = pairing.exact_caddy_pair([caddy()], metadata, response)
        self.assertIsNone(selected)
        self.assertIn("response.remote_port does not match Caddy", errors)

    def test_multiple_tagged_caddy_rows_remain_ambiguous(self) -> None:
        metadata = {"run_id": RUN_ID}
        response = {
            "run_id": RUN_ID, "request_uuid": "uuid-1", "remote_ip": EGRESS,
            "remote_port": 45678, "http_protocol": "HTTP/3.0",
            "request_host": "measurement.example.org", "request_uri": f"/probe/{RUN_ID}",
            "server_unix_ms": int((NOW.timestamp() + 5) * 1000),
        }
        second = caddy()
        second["request_uuid"] = "uuid-2"
        selected, errors = pairing.exact_caddy_pair([caddy(), second], metadata, response)
        self.assertIsNone(selected)
        self.assertIn("expected one tagged Caddy destination row, found 2", errors)
        first = caddy()
        first["ts"] = NOW.timestamp() + 7
        first["_artifact"] = "later.jsonl"
        first["_artifact_sha256"] = "b" * 64
        first["_line_number"] = 9
        first["_row_sha256"] = "c" * 64
        second["ts"] = NOW.timestamp() + 6
        second["_artifact"] = "earlier.jsonl"
        second["_artifact_sha256"] = "d" * 64
        second["_line_number"] = 4
        second["_row_sha256"] = "e" * 64
        sequence = pairing.tagged_caddy_sequence([first, second], metadata, PRIVATE)
        self.assertEqual([item["request_uuid"] for item in sequence], ["uuid-2", "uuid-1"])
        self.assertEqual(sequence[0]["five_tuple"]["destination_ip"], PRIVATE)
        self.assertEqual(sequence[0]["artifact_path"], "earlier.jsonl")

    def test_server_http3_requires_fresh_exact_quic_initial(self) -> None:
        fresh = packet(src_ip=EGRESS, dst_ip=PRIVATE, src_port=45678)
        evidence = pairing.server_flow_evidence(
            [fresh], caddy(), PRIVATE, NOW, NOW + dt.timedelta(seconds=10)
        )
        self.assertTrue(evidence["fresh"])
        self.assertEqual(evidence["transport"], "udp_quic_initial")
        stale = {**fresh, "time_epoch": NOW.timestamp() - 1}
        self.assertFalse(
            pairing.server_flow_evidence(
                [stale], caddy(), PRIVATE, NOW, NOW + dt.timedelta(seconds=10)
            )["fresh"]
        )
        later = {**fresh, "time_epoch": NOW.timestamp() + 6}
        self.assertFalse(
            pairing.server_flow_evidence(
                [later], caddy(), PRIVATE, NOW, NOW + dt.timedelta(seconds=10)
            )["fresh"]
        )
        other_connection = {**fresh, "frame_number": 2, "quic_dcid": "ccdd"}
        ambiguous = pairing.server_flow_evidence(
            [fresh, other_connection], caddy(), PRIVATE, NOW, NOW + dt.timedelta(seconds=10)
        )
        self.assertTrue(ambiguous["fresh"])
        self.assertFalse(ambiguous["ambiguous"])
        self.assertEqual(ambiguous["connection_ids"], ["aabb", "ccdd"])
        wrong_port = {**fresh, "src_port": 45679}
        self.assertFalse(
            pairing.server_flow_evidence(
                [wrong_port], caddy(), PRIVATE, NOW, NOW + dt.timedelta(seconds=10)
            )["fresh"]
        )

    def test_client_contacts_are_ordered_and_direct_origin_is_separate(self) -> None:
        packets = [
            packet(frame_number=7, time_epoch=3, dst_ip=ORIGIN, quic_initial=False, quic_dcid=None),
            packet(frame_number=2, time_epoch=2, dst_ip=ALT),
            packet(frame_number=1, time_epoch=1, transport="tcp", dst_ip=INGRESS, tcp_syn=True, quic_initial=False),
            packet(frame_number=3, time_epoch=1.1, transport="tcp", src_ip=INGRESS, dst_ip=REAL, src_port=443, dst_port=55000, tcp_syn=True, tcp_ack=True, quic_initial=False),
            packet(frame_number=4, time_epoch=1.2, transport="tcp", src_ip=REAL, dst_ip=INGRESS, src_port=55000, dst_port=443, tcp_syn=False, tcp_ack=True, quic_initial=False),
            packet(frame_number=5, time_epoch=2.1, transport="udp", src_ip=ALT, dst_ip=REAL, src_port=443, dst_port=55000, quic_initial=False, quic_dcid=None),
        ]
        result = pairing.client_contacts(
            packets, [INGRESS, ALT], ORIGIN, INGRESS,
            {INGRESS: ["mask-h2.icloud.com"], ALT: ["mask.icloud.com"]},
            0,
            3,
        )
        self.assertEqual([item["destination_ip"] for item in result["contacts"]], [INGRESS, ALT])
        self.assertEqual(result["outer_transport"], "mixed")
        self.assertTrue(result["attributable_tcp"])
        self.assertTrue(result["unambiguous_tcp_fallback"])
        self.assertTrue(result["alternative_udp_failover"])
        self.assertEqual(result["contacts"][0]["hostnames"], ["mask-h2.icloud.com"])
        self.assertEqual(len(result["direct_origin_contacts"]), 1)

    def test_capture_candidate_without_hostname_provenance_is_not_attributed(self) -> None:
        result = pairing.client_contacts(
            [packet(dst_ip=INGRESS)], [INGRESS], ORIGIN, INGRESS, {}, 0, NOW.timestamp() + 2
        )
        self.assertEqual(len(result["contacts"]), 1)
        self.assertEqual(result["attributable_contacts"], [])
        self.assertFalse(result["attributable_tcp"])
        self.assertFalse(result["unambiguous_tcp_fallback"])
        self.assertEqual(result["outer_transport"], "none")

    def test_multiple_tcp_setup_flows_are_not_an_unambiguous_fallback(self) -> None:
        packets = [
            packet(
                frame_number=1,
                time_epoch=NOW.timestamp() + 1,
                transport="tcp",
                tcp_syn=True,
                quic_initial=False,
                src_port=50001,
            ),
            packet(
                frame_number=2,
                time_epoch=NOW.timestamp() + 2,
                transport="tcp",
                tcp_syn=True,
                quic_initial=False,
                src_port=50002,
            ),
        ]
        result = pairing.client_contacts(
            packets,
            [INGRESS],
            ORIGIN,
            INGRESS,
            {INGRESS: ["mask-h2.icloud.com"]},
            NOW.timestamp(),
            NOW.timestamp() + 3,
        )
        self.assertTrue(result["attributable_tcp"])
        self.assertFalse(result["unambiguous_tcp_fallback"])

    def test_tcp_handshake_after_attribution_window_does_not_establish_fallback(self) -> None:
        packets = [
            packet(
                frame_number=1,
                time_epoch=NOW.timestamp() + 1,
                transport="tcp",
                tcp_syn=True,
                quic_initial=False,
            ),
            packet(
                frame_number=2,
                time_epoch=NOW.timestamp() + 4,
                transport="tcp",
                src_ip=INGRESS,
                dst_ip=REAL,
                src_port=443,
                dst_port=55000,
                tcp_syn=True,
                tcp_ack=True,
                quic_initial=False,
            ),
            packet(
                frame_number=3,
                time_epoch=NOW.timestamp() + 5,
                transport="tcp",
                tcp_syn=False,
                tcp_ack=True,
                quic_initial=False,
            ),
        ]
        result = pairing.client_contacts(
            packets,
            [INGRESS],
            ORIGIN,
            INGRESS,
            {INGRESS: ["mask-h2.icloud.com"]},
            NOW.timestamp(),
            NOW.timestamp() + 2,
        )
        self.assertFalse(result["unambiguous_tcp_fallback"])
        self.assertIsNone(result["contacts"][0]["tcp_handshake_evidence"])

    def test_origin_in_capture_scope_is_never_an_outer_candidate(self) -> None:
        result = pairing.client_contacts(
            [packet(dst_ip=ORIGIN)], [INGRESS, ORIGIN], ORIGIN, INGRESS,
            {ORIGIN: ["measurement.example.org"]}, 0, NOW.timestamp() + 2,
        )
        self.assertEqual(result["contacts"], [])
        self.assertEqual(len(result["direct_origin_contacts"]), 1)

    def test_pf_block_requires_exact_rule_and_positive_counter_delta(self) -> None:
        rule = (
            f"block drop out quick on en0 inet proto udp from any to {INGRESS} "
            'port = 443 label "icpr-protocol-diagnostic-v1-udp-block"'
        )
        firewall = {
            "anchor": "com.apple/icpr-protocol-diagnostic-v1",
            "condition": "udp_blocked",
            "previous_anchor_rules": "",
            "exact_rule": rule,
            "loaded_rules_snapshot": rule,
            "rule_loaded": True,
            "prepared_utc": "2026-08-03T06:59:59Z",
            "rule_load_started_utc": "2026-08-03T07:00:00Z",
            "rule_load_completed_utc": "2026-08-03T07:00:00.500000Z",
            "statistics_after_load_utc": "2026-08-03T07:00:01Z",
            "targeted_state_reset_utc": "2026-08-03T07:00:02Z",
            "statistics_before_cleanup_utc": "2026-08-03T07:00:10Z",
            "restored_utc": "2026-08-03T07:00:11Z",
            "statistics_after_load": {"packets": 0},
            "statistics_before_cleanup": {"packets": 2},
        }
        result = pairing.pf_counter_result(firewall, INGRESS, "udp_blocked", "en0")
        self.assertTrue(result["enforced"])
        self.assertEqual(result["delta"], 2)
        firewall["statistics_before_cleanup"] = {"packets": 0}
        self.assertFalse(
            pairing.pf_counter_result(firewall, INGRESS, "udp_blocked", "en0")["enforced"]
        )

    def test_permitted_pf_evidence_requires_empty_anchor_and_chronology(self) -> None:
        firewall = {
            "anchor": "com.apple/icpr-protocol-diagnostic-v1",
            "condition": "udp_permitted",
            "previous_anchor_rules": "",
            "exact_rule": "",
            "loaded_rules_snapshot": "",
            "rule_loaded": False,
            "prepared_utc": "2026-08-03T07:00:00Z",
            "statistics_after_load_utc": "2026-08-03T07:00:01Z",
            "statistics_before_cleanup_utc": "2026-08-03T07:00:10Z",
            "restored_utc": "2026-08-03T07:00:11Z",
            "statistics_after_load": {},
            "statistics_before_cleanup": {},
        }
        result = pairing.pf_counter_result(firewall, INGRESS, "udp_permitted", "en0")
        self.assertTrue(result["valid"])
        self.assertTrue(result["chronology_valid"])
        firewall["restored_utc"] = "2026-08-03T06:59:59Z"
        self.assertFalse(
            pairing.pf_counter_result(firewall, INGRESS, "udp_permitted", "en0")["valid"]
        )

    def test_strong_fallback_needs_pf_tcp_h3_server_quic_catalogue_and_no_bypass(self) -> None:
        client = {
            "attributable_tcp": True,
            "unambiguous_tcp_fallback": True,
            "alternative_udp_failover": False,
            "direct_origin_contacts": [],
        }
        classification, acceptance, _ = pairing.classify_trial(
            condition="udp_blocked",
            caddy_row=caddy(),
            server_flow={"fresh": True, "transport": "udp_quic_initial"},
            client=client,
            pf={"enforced": True},
            egress_catalogue_match=True,
            real_ip_match=False,
            pairing_errors=[],
            integrity_errors=[],
        )
        self.assertEqual(classification, "outer_tcp_fallback_destination_http3")
        self.assertEqual(acceptance, "supports_strong_fallback")
        client["alternative_udp_failover"] = True
        classification, acceptance, _ = pairing.classify_trial(
            condition="udp_blocked", caddy_row=caddy(),
            server_flow={"fresh": True, "transport": "udp_quic_initial"}, client=client,
            pf={"enforced": True}, egress_catalogue_match=True, real_ip_match=False,
            pairing_errors=[], integrity_errors=[],
        )
        self.assertEqual(classification, "alternative_quic_ingress_failover")
        self.assertEqual(acceptance, "supports_primary_only")

    def test_http3_without_server_quic_is_ambiguous(self) -> None:
        classification, acceptance, _ = pairing.classify_trial(
            condition="udp_permitted", caddy_row=caddy(),
            server_flow={"fresh": False, "transport": "none"},
            client={"direct_origin_contacts": []}, pf={}, egress_catalogue_match=True,
            real_ip_match=False, pairing_errors=[], integrity_errors=[],
        )
        self.assertEqual(classification, "http3_without_fresh_server_quic")
        self.assertEqual(acceptance, "excluded_ambiguous")

    def test_lifecycle_gate_rejects_late_changed_or_unrestored_positive(self) -> None:
        base = ("destination_http3_relayed", "supports_primary", [])
        self.assertEqual(
            pairing.gate_acceptance_by_lifecycle(
                *base,
                outcome="success",
                condition_changed=False,
                cleanup_valid=True,
                deadline_missed=True,
            )[:2],
            ("timeout", "observed_non_supporting"),
        )
        self.assertEqual(
            pairing.gate_acceptance_by_lifecycle(
                *base,
                outcome="success",
                condition_changed=True,
                cleanup_valid=True,
                deadline_missed=False,
            )[:2],
            ("condition_changed", "excluded_ambiguous"),
        )
        self.assertEqual(
            pairing.gate_acceptance_by_lifecycle(
                *base,
                outcome="success",
                condition_changed=False,
                cleanup_valid=False,
                deadline_missed=False,
            )[:2],
            ("integrity_failure", "excluded_ambiguous"),
        )

    def test_pairing_error_is_not_misclassified_as_no_observation(self) -> None:
        classification, acceptance, ambiguities = pairing.classify_trial(
            condition="udp_permitted", caddy_row=None,
            server_flow={"fresh": False, "transport": "none"},
            client={"direct_origin_contacts": []}, pf={}, egress_catalogue_match=False,
            real_ip_match=False, pairing_errors=["UUID mismatch"], integrity_errors=[],
        )
        self.assertEqual(classification, "ambiguous_destination_pairing")
        self.assertEqual(acceptance, "excluded_ambiguous")
        self.assertEqual(ambiguities, ["UUID mismatch"])

    def test_catalogue_longest_prefix_and_same_day_hash(self) -> None:
        rows = [
            {"ip_prefix": "198.51.100.0/24", "country": "ZZ", "region": "EXAMPLE", "city": "A"},
            {"ip_prefix": "198.51.100.0/25", "country": "ZZ", "region": "EXAMPLE", "city": "B"},
        ]
        self.assertEqual(pairing.catalogue_match(EGRESS, rows)["city"], "B")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feed = root / "2026-08-03" / "apple-egress.csv"
            feed.parent.mkdir()
            feed.write_text("198.51.100.0/24,ZZ,EXAMPLE,Test,\n", encoding="utf-8")
            pairing.icprlib.write_sidecar(feed)
            metadata = {
                "apple_feed_path": str(feed),
                "apple_feed_sha256": pairing.icprlib.sha256_file(feed),
                "safari_launch_requested_utc": "2026-08-03T07:00:00Z",
            }
            loaded, evidence = pairing.verify_same_day_feed(metadata, root)
            self.assertIsNotNone(pairing.catalogue_match(EGRESS, loaded))
            self.assertEqual(evidence["sha256"], metadata["apple_feed_sha256"])

    def test_summary_never_pools_conditions_or_retries(self) -> None:
        rows = [
            {"slot_id": "s1", "retry_number": 1, "condition": "udp_permitted", "classification": "old", "acceptance": "excluded_ambiguous"},
            {"slot_id": "s1", "retry_number": 2, "condition": "udp_permitted", "classification": "destination_http3_relayed", "acceptance": "supports_primary"},
            {"slot_id": "s2", "retry_number": 1, "condition": "udp_blocked", "classification": "destination_http2_or_tcp", "acceptance": "observed_non_supporting"},
        ]
        summary = pairing.summarize(rows)
        self.assertEqual(summary["udp_permitted"]["slots"], 1)
        self.assertEqual(summary["udp_permitted"]["attempts_total"], 2)
        self.assertEqual(summary["udp_permitted"]["acceptance_counts"], {"supports_primary": 1})
        self.assertEqual(summary["udp_blocked"]["classification_counts"], {"destination_http2_or_tcp": 1})

    def test_pair_attempt_rejects_an_unfinalized_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / RUN_ID
            attempt.mkdir()
            (attempt / "metadata.json").write_text(
                json.dumps({"run_id": RUN_ID}), encoding="utf-8"
            )
            result = pairing.pair_attempt(attempt, [], Path(temporary), PRIVATE)
            self.assertEqual(result["classification"], "integrity_failure")
            self.assertEqual(result["acceptance"], "excluded_ambiguous")
            self.assertTrue(any("manifest" in item.lower() for item in result["ambiguities"]))

    def test_outputs_refuse_campaign_derived_directory(self) -> None:
        forbidden = pairing.REPO_ROOT / "experiment" / "derived" / "protocol"
        with self.assertRaises(pairing.PairingError):
            pairing.write_outputs([], forbidden)

    def test_outputs_refuse_any_path_outside_diagnostic_derived(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(pairing.PairingError):
                pairing.write_outputs([], Path(temporary))

    def test_outputs_refuse_descendant_subset_directory(self) -> None:
        with self.assertRaises(pairing.PairingError):
            pairing.write_outputs([], pairing.DEFAULT_DERIVED_ROOT / "subset")

    def test_pairing_refuses_descendant_client_subset(self) -> None:
        with self.assertRaises(pairing.PairingError):
            pairing.run(
                pairing.DEFAULT_CLIENT_ROOT / "2026-08-04",
                pairing.DEFAULT_SERVER_ROOT,
                pairing.DEFAULT_DERIVED_ROOT,
                PRIVATE,
            )

    def test_bypass_precedes_deadline_and_condition_change(self) -> None:
        classification, acceptance, _ = pairing.gate_acceptance_by_lifecycle(
            "timeout",
            "observed_non_supporting",
            [],
            outcome="direct_bypass",
            condition_changed=True,
            cleanup_valid=False,
            deadline_missed=True,
        )
        self.assertEqual(classification, "real_ip_bypass")
        self.assertEqual(acceptance, "safety_stop")


if __name__ == "__main__":
    unittest.main()
