from __future__ import annotations

import argparse
import copy
import csv
import datetime as dt
import ipaddress
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

import controller  # noqa: E402
import icprlib  # noqa: E402
from helpers.dns_stub import response_for  # noqa: E402
from pipeline import (  # noqa: E402
    PairingPipeline,
    _parse_response_server_utc,
    _temporal_intersection,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"
SERVER_IP = "10.0.0.10"
INGRESS_IP = "203.0.113.10"
WRONG_INGRESS_IP = "203.0.113.11"
EGRESS_IP = "198.51.100.20"
REAL_IP = "192.0.2.44"
START = "2026-07-16T23:59:50Z"
END = "2026-07-17T00:00:20Z"
SERVER_EPOCH = dt.datetime(2026, 7, 17, 0, 0, 5, tzinfo=dt.timezone.utc).timestamp()


def write_hashed(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    icprlib.write_sidecar(path)


def frozen_config(root: Path, *, allowed_city: str = "Test City") -> Path:
    config = copy.deepcopy(icprlib.load_json_yaml(icprlib.EXAMPLE_CONFIG_PATH))
    config["configuration_status"] = "frozen"
    config["server"]["private_ipv4"] = SERVER_IP
    config["freshness"]["selected_method"] = "A"
    config["daily_schedule"]["target_accepted_per_pinned_block"] = 2
    config["daily_schedule"]["alternation_anchor_date_utc"] = "2026-07-17"
    config["mapping"]["origin_asn_dataset_version"] = "synthetic-2026-07-17"
    config["mapping"]["akamai_sibling_asns"] = [64510, 64520]
    config["mapping"]["origin_asn_file"] = "reference/asn/origin_prefixes.csv"
    config["mapping"]["operator_map_file"] = "reference/asn/operator_map_v1.csv"
    config["objective_3_ground_truth"] = {
        "true_country_code": "ZZ",
        "true_time_zone": "Etc/UTC",
        "country_time_zone_permitted_apple_locations": [
            {"country": "ZZ", "region": "EXAMPLE", "city": "Test City"}
        ],
        "maintain_general_location_boundary": {
            "boundary_id": "synthetic-test-boundary",
            "allowed_country_codes": ["ZZ"],
            "allowed_regions": ["EXAMPLE"],
            "allowed_cities": [allowed_city],
        },
        "temporal_intersection_rule": {
            "rule_id": "exact_advertised_field_intersection",
            "fields": ["country", "region", "city"],
            "comparison_normalization": "trim_casefold_preserve_raw",
        },
        "distance_is_supporting_only": True,
        "advertised_location_is_not_physical_location_proof": True,
        "repeated_unpinned_sequence_is_primary": True,
    }
    path = root / "config" / "experiment_config.yaml"
    icprlib.write_json(path, config)
    return path


def reference_files(root: Path, *, feed_match: bool = True, operator_id: str = "akamai") -> tuple[Path, Path, Path]:
    feed = root / "feeds" / "apple" / "2026-07-17" / "apple-egress.csv"
    feed_prefix = "198.51.100.0/24" if feed_match else "198.51.100.128/25"
    write_hashed(
        feed,
        "ip_prefix,country,region,city\n"
        f"{feed_prefix},ZZ,EXAMPLE,Test City\n",
    )
    asn = root / "reference" / "asn" / "origin_prefixes.csv"
    write_hashed(
        asn,
        "date,prefix,asn,source,source_hash\n"
        f"2026-07-17,203.0.113.0/24,64510,synthetic,{'a' * 64}\n"
        f"2026-07-17,198.51.100.0/24,64520,synthetic,{'a' * 64}\n"
        f"2026-07-17,192.0.2.0/24,64530,synthetic,{'a' * 64}\n",
    )
    operator = root / "reference" / "asn" / "operator_map_v1.csv"
    operator.parent.mkdir(parents=True, exist_ok=True)
    operator.write_text(
        "asn,operator_id,operator_name,mapping_rule,version\n"
        "714,apple,Apple Inc.,explicit synthetic AS714 rule,v1\n"
        f"64510,{operator_id},Synthetic ingress,synthetic sibling rule,v1\n"
        f"64520,{operator_id},Synthetic egress,synthetic sibling rule,v1\n"
        "64530,researcher,Synthetic researcher,synthetic test mapping,v1\n",
        encoding="utf-8",
    )
    icprlib.write_sidecar(operator)
    return feed, asn, operator


def caddy_row(run_id: str, remote_port: int, transport: str, remote_ip: str = EGRESS_IP) -> dict:
    protocol = "HTTP/3.0" if transport == "udp" else "HTTP/2.0"
    return {
        "level": "info",
        "ts": SERVER_EPOCH,
        "request": {
            "remote_ip": remote_ip,
            "remote_port": str(remote_port),
            "proto": protocol,
            "method": "GET",
            "host": "probe.example.org",
            "uri": f"/probe/{run_id}",
        },
        "status": 200,
        "run_id": run_id,
        "request_uuid": f"uuid-{remote_port}",
    }


def build_scenario(
    root: Path,
    *,
    transport: str = "udp",
    mutation: str | None = None,
    run_id: str = "icpr-20260716T235950Z-0011223344556677",
    suffix: str = "",
    allowed_city: str = "Test City",
    response_server_utc: str = "2026-07-17T00:00:05Z",
    private_relay_state: str = "on",
    fallback: bool = False,
) -> tuple[Path, Path, Path, Path, Path]:
    config = frozen_config(root, allowed_city=allowed_city)
    _, asn, operator = reference_files(root, feed_match=mutation != "egress_not_in_feed")
    attempt = root / "client" / "2026-07-16" / f"attempt{suffix or '-one'}"
    attempt.mkdir(parents=True)
    unpinned = mutation in {
        "unpinned_stale_other",
        "legacy_unpinned_stale_other",
    }
    intended = None if unpinned else INGRESS_IP
    metadata = {
        "run_id": run_id,
        "campaign": "synthetic",
        "run_mode": "smoke",
        "session": "adhoc",
        "slot_id": "synthetic-slot-1",
        "retry_number": 1,
        "block_id": "A",
        "attempt_number": 1,
        "client_start_utc": START,
        "safari_launch_requested_utc": "2026-07-16T23:59:59Z",
        "timeout_deadline_utc": "2026-07-17T00:01:29Z",
        "clock_status": "synchronized",
        "clock_evidence": {
            "recorded_utc": START,
            "network_time": "Network Time: On",
            "network_time_server": "Network Time Server: synthetic.invalid",
        },
        "private_relay_state": private_relay_state,
        "location_setting": "maintain_general_location",
        "intended_ingress_group": "unpinned" if unpinned else "akamai",
        "intended_ingress_ip": intended,
        "approved_ingress_candidates": [INGRESS_IP, WRONG_INGRESS_IP],
        "approved_pin_group_addresses": [] if unpinned else [INGRESS_IP],
        "pin_list_version": "synthetic-v1",
        "pin_list_sha256": "a" * 64,
        "effective_dns": {
            "recorded_utc": START,
            "hostnames": {
                "mask.icloud.com": {"A": [{"address": INGRESS_IP, "ttl": 30}], "AAAA": []},
                "mask-h2.icloud.com": {"A": [{"address": INGRESS_IP, "ttl": 30}], "AAAA": []},
            },
        },
        "capture_filter": f"host {INGRESS_IP} and (tcp port 443 or udp port 443)",
        "quic_block_state": "targeted_ingress_udp_443" if fallback else "not_blocked",
        "hostname": "probe.example.org",
        "url": f"https://probe.example.org/probe/{run_id}",
        "macos_version": "synthetic",
        "safari_version": "synthetic",
        "active_interface": "en0",
        "network_type": "wifi",
        "real_public_ipv4": EGRESS_IP if mutation == "real_ip" else REAL_IP,
        "freshness_method": "A",
        **(
            {"ingress_attribution_policy": "legacy_candidate_contact_v1"}
            if mutation == "legacy_unpinned_stale_other"
            else {"ingress_attribution_policy": "bounded_candidate_contact_v2"}
        ),
        "controller_version": "1.0.0",
        "config_version": "step9-test-v1",
        "config_sha256": icprlib.sha256_file(config),
        "operator_condition_confirmation": "synthetic fixed condition",
    }
    icprlib.write_json(attempt / "metadata.json", metadata)
    icprlib.append_jsonl(
        attempt / "events.jsonl",
        {"event": "run_started", "recorded_utc": START, **metadata},
    )
    icprlib.append_jsonl(
        attempt / "events.jsonl",
        {
            "event": "safari_url_launch_requested",
            "recorded_utc": "2026-07-16T23:59:59Z",
            "url": metadata["url"],
        },
    )
    icprlib.append_jsonl(
        attempt / "events.jsonl",
        {"event": "capture_stopped", "recorded_utc": "2026-07-17T00:00:19Z"},
    )
    icprlib.append_jsonl(
        attempt / "events.jsonl",
        {
            "event": "run_finished",
            "recorded_utc": END,
            "outcome": "success",
            "condition_changed": mutation == "condition_changed",
            "end_condition_confirmation": "synthetic fixed condition unchanged",
        },
    )
    remote_port = 50000
    response = {
        "run_id": run_id,
        "server_utc": response_server_utc,
        "server_unix_ms": int(SERVER_EPOCH * 1000),
        "request_uuid": f"uuid-{remote_port}",
        "remote_ip": EGRESS_IP,
        "remote_port": str(remote_port),
        "http_protocol": "HTTP/3.0" if transport == "udp" else "HTTP/2.0",
        "request_host": "probe.example.org",
        "request_uri": f"/probe/{run_id}",
    }
    icprlib.write_json(attempt / "response.json", response)
    ingress_contact = WRONG_INGRESS_IP if mutation == "wrong_ingress" else INGRESS_IP
    client_packet = {
        "frame_number": 1,
        "time_epoch": SERVER_EPOCH - 3,
        "src_ip": "10.1.1.5",
        "dst_ip": ingress_contact,
        "transport": transport,
        "src_port": 40000,
        "dst_port": 443,
        "tcp_syn": transport == "tcp",
        "tcp_ack": False,
        "tcp_len": 100 if transport == "tcp" else 0,
        "stream": 1,
        "udp_length": 1200 if transport == "udp" else 0,
        "quic_initial": transport == "udp",
        "quic_dcid": "11223344" if transport == "udp" else "",
    }
    client_packets = [client_packet]
    if mutation in {
        "unpinned_stale_other",
        "legacy_unpinned_stale_other",
        "intended_and_other_fresh",
    }:
        other_packet = dict(client_packet)
        other_packet.update(
            frame_number=2,
            time_epoch=SERVER_EPOCH - 4,
            dst_ip=WRONG_INGRESS_IP,
            src_port=40001,
        )
        if mutation in {"unpinned_stale_other", "legacy_unpinned_stale_other"}:
            other_packet.update(
                transport="udp",
                tcp_syn=False,
                tcp_ack=False,
                tcp_len=0,
                udp_length=400,
                quic_initial=False,
                quic_dcid="",
            )
        client_packets.insert(0, other_packet)
    if mutation == "post_response_other_ingress":
        later_packet = dict(client_packet)
        later_packet.update(
            frame_number=2,
            time_epoch=SERVER_EPOCH + 5,
            dst_ip=WRONG_INGRESS_IP,
            src_port=40001,
        )
        client_packets.append(later_packet)
    if fallback:
        blocked_udp = dict(client_packet)
        blocked_udp.update(
            frame_number=2,
            time_epoch=SERVER_EPOCH - 3.5,
            transport="udp",
            src_port=40001,
            tcp_syn=False,
            tcp_len=0,
            udp_length=1200,
        )
        client_packets.insert(0, blocked_udp)
        icprlib.write_json(
            attempt / "firewall-state.json",
            {
                "anchor": "com.apple/icpr-step9",
                "exact_rule": (
                    f"block drop out quick on en0 inet proto udp from any to "
                    f"{INGRESS_IP} port = 443 label \"icpr-step9-udp-block\""
                ),
                "targeted_state_reset_utc": "2026-07-16T23:59:55Z",
                "rule_statistics_before_cleanup_utc": "2026-07-17T00:00:18Z",
                "rule_statistics_before_cleanup": {
                    "evaluations": 10,
                    "packets": 1,
                    "bytes": 1200,
                    "states": 0,
                },
                "restored_utc": "2026-07-17T00:00:19Z",
            },
        )
    (attempt / "client.packets.jsonl").write_text(
        "".join(json.dumps(packet) + "\n" for packet in client_packets),
        encoding="utf-8",
    )
    icprlib.finalize_attempt(attempt)
    if mutation == "corrupt_hash":
        metadata_path = attempt / "metadata.json"
        metadata_path.chmod(0o640)
        metadata_path.write_text(metadata_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    server = root / "server"
    rows = [] if mutation == "no_server" else [caddy_row(run_id, remote_port, transport)]
    if mutation == "multiple_server_flows":
        rows.append(caddy_row(run_id, remote_port + 1, transport))
    access = server / "access.jsonl"
    write_hashed(access, "".join(json.dumps(row) + "\n" for row in rows))
    packet_transport = transport
    server_packet = {
        "frame_number": 10,
        "time_epoch": SERVER_EPOCH - 2,
        "src_ip": EGRESS_IP,
        "dst_ip": SERVER_IP,
        "transport": packet_transport,
        "src_port": remote_port,
        "dst_port": 443,
        "tcp_syn": packet_transport == "tcp" and mutation != "no_fresh_flow",
        "tcp_ack": False,
        "stream": 1,
        "udp_length": 1200 if packet_transport == "udp" else 0,
        "quic_initial": packet_transport == "udp" and mutation != "no_fresh_flow",
        "quic_dcid": "aabbccdd" if packet_transport == "udp" and mutation != "no_fresh_flow" else "",
    }
    packets = server / "server.packets.jsonl"
    write_hashed(packets, json.dumps(server_packet) + "\n")
    return config, attempt, server, asn, operator


class PairingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenarios = json.loads((FIXTURES / "scenarios.json").read_text(encoding="utf-8"))

    def run_scenario(self, scenario: dict) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root,
                transport=scenario["transport"],
                mutation=scenario.get("mutation"),
            )
            pipeline = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            )
            records = pipeline.run()
            self.assertEqual(len(records), 1)
            return records[0]

    def test_valid_tcp_and_quic(self) -> None:
        for name in ("valid_tcp", "valid_quic"):
            with self.subTest(name=name):
                scenario = self.scenarios[name]
                row = self.run_scenario(scenario)
                self.assertEqual(row["disposition"], scenario["expected_disposition"])
                self.assertEqual(row["protocol_classification"], scenario["expected_protocol"])
                self.assertTrue(row["freshness_evidence"])
                self.assertTrue(row["same_operator"])
                self.assertEqual(
                    row["pin_contact_status"], "intended_ingress_observed"
                )

    def test_relay_off_http3_control_is_not_labelled_as_a_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root,
                transport="udp",
                mutation="real_ip",
                private_relay_state="off_control",
            )
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(row["exclusion_reason"], "E05_REAL_IP_AT_DESTINATION")
            self.assertEqual(row["protocol_classification"], "direct_http3_control")
            self.assertIn("expected real IP", row["protocol_classification_basis"])

    def test_caddy_go_response_timestamp_is_accepted_and_cross_checked(self) -> None:
        go_timestamp = (
            "2026-07-17 00:00:05.000000000 +0000 UTC m=+93788.833319108"
        )
        parsed = _parse_response_server_utc(go_timestamp)
        self.assertEqual(
            parsed,
            dt.datetime(2026, 7, 17, 0, 0, 5, tzinfo=dt.timezone.utc),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, response_server_utc=go_timestamp
            )
            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(result["disposition"], "accepted")
        with self.assertRaises(icprlib.IcprError):
            _parse_response_server_utc(
                "2026-07-17 00:00:05 +0200 CEST m=+93788.833319108"
            )

    def test_each_exclusion(self) -> None:
        for name in ("E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08"):
            with self.subTest(name=name):
                scenario = self.scenarios[name]
                row = self.run_scenario(scenario)
                self.assertEqual(row["disposition"], "excluded")
                self.assertEqual(row["exclusion_reason"], scenario["expected_exclusion"])
                if name == "E04":
                    self.assertEqual(row["pin_contact_status"], "other_ingress_observed")

    def test_post_response_ingress_probe_does_not_create_false_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, mutation="post_response_other_ingress"
            )
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(row["disposition"], "accepted")
            self.assertEqual(row["observed_ingress_ip"], INGRESS_IP)
            self.assertEqual(row["pin_contact_status"], "intended_ingress_observed")
            self.assertEqual(
                {item["ingress_ip"] for item in row["client_ingress_candidates"]},
                {INGRESS_IP},
            )

    def test_unpinned_stale_contact_does_not_override_one_fresh_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, mutation="unpinned_stale_other"
            )
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(row["disposition"], "accepted")
            self.assertEqual(row["observed_ingress_ip"], INGRESS_IP)
            self.assertEqual(
                {item["ingress_ip"] for item in row["client_ingress_candidates"]},
                {INGRESS_IP, WRONG_INGRESS_IP},
            )
            self.assertEqual(
                {
                    item["ingress_ip"]
                    for item in row["client_fresh_ingress_candidates"]
                },
                {INGRESS_IP},
            )

    def test_pinned_intended_and_other_fresh_handshakes_remain_e04(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, mutation="intended_and_other_fresh"
            )
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(row["disposition"], "accepted")
            self.assertEqual(row["observed_ingress_ip"], INGRESS_IP)
            self.assertEqual(
                row["fresh_pin_contact_status"],
                "intended_and_other_ingresses_observed",
            )
            self.assertEqual(
                {
                    item["ingress_ip"]
                    for item in row["client_ingress_attribution_candidates"]
                },
                {INGRESS_IP},
            )

    def test_historical_attempt_without_policy_keeps_legacy_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, mutation="legacy_unpinned_stale_other"
            )
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(
                row["ingress_attribution_policy"],
                "legacy_candidate_contact_v1",
            )
            self.assertEqual(row["disposition"], "excluded")
            self.assertEqual(
                row["exclusion_reason"], "E04_WRONG_OR_UNKNOWN_INGRESS"
            )

    def test_duplicate_run_id_is_e07(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root, suffix="-a")
            second_root = root / "second-build"
            _, second, _, _, _ = build_scenario(second_root, suffix="-b")
            destination = root / "client" / "2026-07-16" / "attempt-b"
            shutil_copytree(second, destination)
            pipeline = PairingPipeline(
                experiment_root=root,
                config_path=config,
                client_root=root / "client",
                server_root=server,
                feed_root=root / "feeds" / "apple",
                asn_path=asn,
                operator_map_path=operator,
            )
            records = pipeline.run()
            self.assertEqual(len(records), 2)
            self.assertTrue(
                all(row["exclusion_reason"] == "E07_CLOCK_OR_LOG_CORRUPTION" for row in records)
            )

    def test_operator_map_versioning_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root)
            first = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(first["ingress_operator"], "akamai")
            config_data = icprlib.load_json_yaml(config)
            config_data["mapping"]["operator_map_version"] = "v2"
            icprlib.write_json(config, config_data)
            replacement = root / "reference" / "asn" / "operator_map_v2.csv"
            replacement.write_text(
                "asn,operator_id,operator_name,mapping_rule,version\n"
                "714,apple,Apple Inc.,explicit synthetic AS714 rule,v2\n"
                "64510,akamai,Synthetic ingress,reclassified synthetic rule,v2\n"
                "64520,akamai,Synthetic egress,reclassified synthetic rule,v2\n"
                "64530,researcher,Synthetic researcher,synthetic test mapping,v2\n",
                encoding="utf-8",
            )
            icprlib.write_sidecar(replacement)
            second = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=replacement,
            ).run()[0]
            self.assertEqual(second["operator_map_version"], "v2")
            self.assertEqual(second["ingress_operator"], "akamai")
            self.assertNotEqual(first["operator_map_sha256"], second["operator_map_sha256"])

    def test_incomplete_objective_three_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root)
            value = icprlib.load_json_yaml(config)
            value["objective_3_ground_truth"]["maintain_general_location_boundary"] = None
            icprlib.write_json(config, value)
            row = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(row["disposition"], "pending")
            self.assertEqual(row["pending_reason"], "objective_3_configuration_incomplete")

    def test_utc_boundary_uses_server_day_feed(self) -> None:
        row = self.run_scenario(self.scenarios["valid_quic"])
        self.assertEqual(row["client_start_utc"][:10], "2026-07-16")
        self.assertEqual(row["server_time_utc"][:10], "2026-07-17")
        self.assertEqual(row["apple_feed_date"], "2026-07-17")

    def test_native_headerless_apple_feed_is_accepted_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, allowed_city="Example City"
            )
            feed = root / "feeds" / "apple" / "2026-07-17" / "apple-egress.csv"
            feed.write_text(
                f"{EGRESS_IP}/32,ZZ,EXAMPLE,EXAMPLE CITY,\n", encoding="utf-8"
            )
            icprlib.write_sidecar(feed)
            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(result["disposition"], "accepted")
            self.assertEqual(result["advertised_country"], "ZZ")
            self.assertEqual(result["advertised_region"], "EXAMPLE")
            self.assertEqual(result["advertised_city"], "EXAMPLE CITY")
            self.assertEqual(result["disclosure_class"], "city_level_consistent")
            self.assertEqual(result["apple_feed_hash"], icprlib.sha256_file(feed))

    def test_primary_city_boundary_normalizes_but_preserves_apple_values(self) -> None:
        cases = (
            ("ZZ", "EXAMPLE", " Example City ", "city_level_consistent"),
            ("ZZ", "EXAMPLE", "Other City", "primary_boundary_non_match"),
            ("YY", "OTHER", "Different City", "inconsistent"),
            ("ZZ", "", "", "unclassifiable"),
        )
        for country, region, city, expected in cases:
            with self.subTest(country=country, region=region, city=city), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config, _, server, asn, operator = build_scenario(
                    root, allowed_city="Example City"
                )
                feed = root / "feeds" / "apple" / "2026-07-17" / "apple-egress.csv"
                feed.write_text(
                    f"{EGRESS_IP}/32,{country},{region},{city},\n",
                    encoding="utf-8",
                )
                icprlib.write_sidecar(feed)
                result = PairingPipeline(
                    experiment_root=root,
                    config_path=config,
                    server_root=server,
                    asn_path=asn,
                    operator_map_path=operator,
                ).run()[0]
                self.assertEqual(result["advertised_country"], country)
                self.assertEqual(result["advertised_region"], region)
                self.assertEqual(result["advertised_city"], city)
                self.assertEqual(result["disclosure_class"], expected)

    def test_temporal_rule_normalizes_values_and_preserves_raw_spellings(self) -> None:
        declaration = {
            "rule_id": "exact_advertised_field_intersection",
            "fields": ["country", "city"],
            "comparison_normalization": "trim_casefold_preserve_raw",
        }
        sequence = [
            {
                "run_id": "one",
                "disposition": "accepted",
                "advertised_country": "ZZ",
                "advertised_city": "Example City",
            },
            {
                "run_id": "two",
                "disposition": "accepted",
                "advertised_country": " zz ",
                "advertised_city": "EXAMPLE CITY",
            },
        ]
        result = _temporal_intersection(declaration, sequence)
        self.assertEqual(result["status"], "evaluated")
        self.assertEqual(
            result["result"],
            {"country": ["zz"], "city": ["example city"]},
        )
        self.assertEqual(
            result["observed_raw_values"]["city"],
            ["EXAMPLE CITY", "Example City"],
        )
        self.assertTrue(result["all_declared_fields_have_nonempty_intersection"])

    def test_versioned_output_names_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root)
            pipeline = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            )
            outputs = pipeline.write_outputs(pipeline.run())
            self.assertEqual(outputs["pairs"].name, "pairs_v1.csv")
            self.assertEqual(outputs["exclusions"].name, "exclusions_v1.csv")
            self.assertEqual(outputs["protocols"].name, "protocol_classification_v1.csv")
            self.assertEqual(outputs["summary"].name, "daily_summary_v1.json")
            for name in ("pairs", "exclusions", "protocols", "summary", "report"):
                self.assertEqual(
                    icprlib.verify_sidecar(outputs[name]),
                    icprlib.sha256_file(outputs[name]),
                )
            with outputs["pairs"].open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["run_mode"], "smoke")
            self.assertEqual(rows[0]["session"], "adhoc")
            self.assertEqual(rows[0]["slot_id"], "synthetic-slot-1")
            self.assertTrue(rows[0]["client_manifest_sha256"])
            self.assertTrue(rows[0]["caddy_artifact_sha256"])
            self.assertTrue(rows[0]["origin_asn_dataset_sha256"])
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            daily = summary["days"]["2026-07-16"]
            self.assertEqual(daily["attempt_counts"], {"accepted": 1, "attempts": 1})
            self.assertEqual(
                daily["strata"]["pin_mode"]["pinned"],
                {"accepted": 1, "attempts": 1},
            )
            self.assertEqual(
                daily["strata"]["location_setting"]["maintain_general_location"],
                {"accepted": 1, "attempts": 1},
            )

    def test_quic_zero_rtt_and_handshake_are_not_freshness_evidence(self) -> None:
        for packet_type in ("1", "2"):
            with self.subTest(packet_type=packet_type), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config, _, server, asn, operator = build_scenario(root, transport="udp")
                packets = server / "server.packets.jsonl"
                row = json.loads(packets.read_text(encoding="utf-8"))
                row.pop("quic_initial")
                row.pop("quic_dcid")
                row["quic.long.packet_type"] = packet_type
                row["quic.dcid"] = "aabbccdd"
                packets.write_text(json.dumps(row) + "\n", encoding="utf-8")
                icprlib.write_sidecar(packets)
                result = PairingPipeline(
                    experiment_root=root,
                    config_path=config,
                    server_root=server,
                    asn_path=asn,
                    operator_map_path=operator,
                ).run()[0]
                self.assertEqual(result["exclusion_reason"], "E03_NO_FRESH_FLOW")
                self.assertEqual(result["freshness_evidence"], "")

    def test_quic_dcid_evolution_remains_one_fresh_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root, transport="udp")
            packets = server / "server.packets.jsonl"
            first = json.loads(packets.read_text(encoding="utf-8"))
            evolved = dict(first)
            evolved["frame_number"] = 11
            evolved["time_epoch"] = SERVER_EPOCH - 1.9
            evolved["quic_dcid"] = "11223344"
            packets.write_text(
                json.dumps(first) + "\n" + json.dumps(evolved) + "\n",
                encoding="utf-8",
            )
            icprlib.write_sidecar(packets)
            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(result["disposition"], "accepted")
            self.assertEqual(
                result["freshness_evidence"]["initial_dcids"],
                ["aabbccdd", "11223344"],
            )

    def test_mixed_http3_then_tcp_delivery_is_explicitly_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root, transport="tcp")
            run_id = "icpr-20260716T235950Z-0011223344556677"
            access = server / "access.jsonl"
            tcp_row = json.loads(access.read_text(encoding="utf-8"))
            h3_row = caddy_row(run_id, 49999, "udp")
            h3_row["ts"] = SERVER_EPOCH - 0.2
            access.write_text(
                json.dumps(h3_row) + "\n" + json.dumps(tcp_row) + "\n",
                encoding="utf-8",
            )
            icprlib.write_sidecar(access)

            packets = server / "server.packets.jsonl"
            tcp_packet = json.loads(packets.read_text(encoding="utf-8"))
            quic_packet = {
                "frame_number": 9,
                "time_epoch": SERVER_EPOCH - 0.3,
                "src_ip": EGRESS_IP,
                "dst_ip": SERVER_IP,
                "transport": "udp",
                "src_port": 49999,
                "dst_port": 443,
                "udp_length": 1200,
                "quic_initial": True,
                "quic_dcid": "feedbeef",
            }
            packets.write_text(
                json.dumps(quic_packet) + "\n" + json.dumps(tcp_packet) + "\n",
                encoding="utf-8",
            )
            icprlib.write_sidecar(packets)

            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(
                result["exclusion_reason"], "E02_MULTIPLE_SERVER_CONNECTIONS"
            )
            self.assertEqual(
                result["protocol_classification"],
                "mixed_http3_then_tcp_delivery",
            )
            self.assertEqual(result["server_delivery_count"], 2)
            self.assertEqual(
                [item["transport"] for item in result["server_delivery_sequence"]],
                ["udp", "tcp"],
            )

    def test_targeted_fallback_uses_tcp_and_positive_pf_counter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(
                root, transport="tcp", fallback=True
            )
            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(result["disposition"], "accepted")
            self.assertEqual(result["ingress_transport"], "tcp")
            self.assertEqual(
                result["fallback_pf_evidence"]["rule_statistics_before_cleanup"][
                    "packets"
                ],
                1,
            )
            self.assertEqual(result["fallback_mask_h2_dns_queries"], [])

    def test_flow_first_observed_before_safari_launch_is_not_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _, server, asn, operator = build_scenario(root, transport="tcp")
            packets = server / "server.packets.jsonl"
            later = json.loads(packets.read_text(encoding="utf-8"))
            earlier = dict(later)
            earlier["frame_number"] = 9
            earlier["time_epoch"] = SERVER_EPOCH - 7
            packets.write_text(
                json.dumps(earlier) + "\n" + json.dumps(later) + "\n",
                encoding="utf-8",
            )
            icprlib.write_sidecar(packets)
            result = PairingPipeline(
                experiment_root=root,
                config_path=config,
                server_root=server,
                asn_path=asn,
                operator_map_path=operator,
            ).run()[0]
            self.assertEqual(result["exclusion_reason"], "E03_NO_FRESH_FLOW")
            self.assertEqual(result["freshness_evidence"], "")


class ConfigurationAndHelperTests(unittest.TestCase):
    def test_rehearsal_may_precede_campaign_anchor(self) -> None:
        anchor = dt.date(2026, 7, 21)
        self.assertEqual(controller.schedule_parity(anchor, anchor), "odd")
        self.assertEqual(
            controller.schedule_parity(dt.date(2026, 7, 20), anchor), "even"
        )

    def test_targeted_firewall_plan_is_scoped_and_auditable(self) -> None:
        config = icprlib.load_json_yaml(icprlib.EXAMPLE_CONFIG_PATH)
        plan = controller.firewall_plan(config, INGRESS_IP, "en0")
        self.assertIn("block drop out quick on en0 inet proto udp", plan["exact_rule"])
        self.assertIn(f"to {INGRESS_IP} port = 443", plan["exact_rule"])
        self.assertIn('label "icpr-step9-udp-block"', plan["exact_rule"])
        self.assertIn("confirmed pinned ingress", plan["targeted_state_reset"])
        self.assertFalse(plan["global_udp_443_block"])

    def test_capture_reuses_finalized_candidates_across_recent_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = Path(temporary) / "client"
            day = "2026-07-20"

            matching = client / day / "matching"
            matching.mkdir(parents=True)
            icprlib.write_json(
                matching / "metadata.json",
                {
                    "campaign": "smoke-v2",
                    "session": "adhoc",
                    "approved_ingress_candidates": ["192.0.2.20"],
                    "intended_ingress_ip": "192.0.2.29",
                    "dns_ingress_candidates": ["192.0.2.21"],
                    "effective_dns": {
                        "hostnames": {
                            "mask.apple-dns.net": {
                                "A": [{"address": "192.0.2.29"}]
                            }
                        }
                    },
                },
            )
            (matching / "manifest.sha256").touch()

            other_session = client / day / "other-session"
            other_session.mkdir()
            icprlib.write_json(
                other_session / "metadata.json",
                {
                    "campaign": "smoke-v2",
                    "session": "evening",
                    "approved_ingress_candidates": ["192.0.2.30"],
                    "macos_effective_ingress_candidates": ["192.0.2.31"],
                },
            )
            (other_session / "manifest.sha256").touch()

            previous_day = client / "2026-07-19" / "previous-day"
            previous_day.mkdir(parents=True)
            icprlib.write_json(
                previous_day / "metadata.json",
                {
                    "campaign": "different-campaign",
                    "session": "morning",
                    "approved_ingress_candidates": ["192.0.2.35"],
                    "effective_dns": {
                        "hostnames": {
                            "mask.apple-dns.net": {
                                "A": [{"address": "192.0.2.36"}]
                            }
                        }
                    },
                },
            )
            (previous_day / "manifest.sha256").touch()

            older_day = client / "2026-07-18" / "older-day"
            older_day.mkdir(parents=True)
            icprlib.write_json(
                older_day / "metadata.json",
                {
                    "approved_ingress_candidates": ["192.0.2.37"],
                    "dns_ingress_candidates": ["192.0.2.38"],
                },
            )
            (older_day / "manifest.sha256").touch()

            unfinished = client / day / "unfinished"
            unfinished.mkdir()
            icprlib.write_json(
                unfinished / "metadata.json",
                {
                    "campaign": "smoke-v2",
                    "session": "adhoc",
                    "approved_ingress_candidates": ["192.0.2.40"],
                    "dns_ingress_candidates": ["192.0.2.41"],
                },
            )

            candidates, provenance = controller.recent_capture_candidate_evidence(
                day,
                lookback_days=1,
                client_root=client,
            )
            self.assertEqual(
                candidates,
                [
                    "192.0.2.21",
                    "192.0.2.29",
                    "192.0.2.31",
                    "192.0.2.36",
                ],
            )
            self.assertEqual(
                controller.recent_capture_candidates(
                    day,
                    lookback_days=1,
                    client_root=client,
                ),
                candidates,
            )
            by_address = {item["address"]: item for item in provenance}
            self.assertEqual(
                by_address["192.0.2.21"]["source_fields"],
                ["dns_ingress_candidates"],
            )
            self.assertEqual(
                by_address["192.0.2.36"]["source_fields"],
                ["effective_dns.hostnames.mask.apple-dns.net.A"],
            )
            self.assertNotIn("192.0.2.20", by_address)
            self.assertNotIn("192.0.2.30", by_address)
            self.assertNotIn("192.0.2.35", by_address)

    def test_pf_rule_statistics_parser(self) -> None:
        snapshot = (
            'block drop out quick on en0 inet proto udp label "icpr-step9-udp-block"\n'
            '  [ Evaluations: 17 Packets: 3 Bytes: 3600 States: 0 ]\n'
        )
        self.assertEqual(
            controller.pf_rule_statistics(snapshot),
            {"evaluations": 17, "packets": 3, "bytes": 3600, "states": 0},
        )

    def test_example_configuration_is_neutral_and_not_frozen(self) -> None:
        config = icprlib.load_json_yaml(icprlib.EXAMPLE_CONFIG_PATH)
        gaps = icprlib.configuration_gaps(config)
        self.assertIn("freshness.selected_method must be frozen after the pilot", gaps)
        self.assertIn(
            "daily_schedule.target_accepted_per_pinned_block must be frozen after the pilot",
            gaps,
        )
        self.assertIn("configuration_status must be frozen", gaps)
        self.assertEqual(config["server"]["hostname"], "probe.example.org")
        self.assertEqual(config["configuration_status"], "template")
        self.assertGreater(
            config["timeout_and_retry"]["operator_completion_grace_seconds"],
            config["timeout_and_retry"]["browser_response_timeout_seconds"],
        )

    def test_dns_stub_a_aaaa_https_and_resolver_discovery(self) -> None:
        def query(qtype: int, name: bytes = b"\x04mask\x06icloud\x03com\x00") -> bytes:
            return struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + name + struct.pack(
                "!HH", qtype, 1
            )

        a = response_for(query(1), INGRESS_IP, 30)
        aaaa = response_for(query(28), INGRESS_IP, 30)
        https = response_for(query(65), INGRESS_IP, 30)
        discovery = response_for(
            query(64, b"\x04_dns\x08resolver\x04arpa\x00"), INGRESS_IP, 30
        )
        self.assertEqual(struct.unpack("!HHHHHH", a[:12])[3], 1)
        self.assertEqual(struct.unpack("!HHHHHH", aaaa[:12])[3], 0)
        self.assertEqual(a[-4:], ipaddress.ip_address(INGRESS_IP).packed)
        self.assertEqual(struct.unpack("!HHHHHH", aaaa[:12])[4], 1)
        self.assertEqual(struct.unpack("!HHHHHH", https[:12])[3:5], (0, 1))
        discovery_header = struct.unpack("!HHHHHH", discovery[:12])
        self.assertEqual(discovery_header[1] & 0xF, 3)
        self.assertEqual(discovery_header[4], 1)

    def test_hosts_override_targets_only_private_relay_cname(self) -> None:
        baseline = b"127.0.0.1 localhost\n::1 localhost\n"
        applied = controller.render_hosts_override(
            baseline, "mask.apple-dns.net", INGRESS_IP
        )
        self.assertTrue(applied.startswith(baseline))
        self.assertEqual(
            controller.hosts_target_entries(applied, "mask.apple-dns.net"),
            [
                {
                    "line_number": 3,
                    "address": INGRESS_IP,
                    "line": f"{INGRESS_IP}\tmask.apple-dns.net\t# icpr-step9 temporary",
                }
            ],
        )

    def test_hosts_override_rejects_an_existing_target(self) -> None:
        baseline = b"127.0.0.1 localhost\n203.0.113.7 mask.apple-dns.net\n"
        with self.assertRaises(icprlib.IcprError):
            controller.render_hosts_override(
                baseline, "mask.apple-dns.net", INGRESS_IP
            )

    def test_effective_hosts_lookup_separates_address_families(self) -> None:
        output = (
            "name: mask.apple-dns.net\n"
            "ipv6_address: 2001:db8::1\n\n"
            "name: mask.apple-dns.net\n"
            f"ip_address: {INGRESS_IP}\n"
        )
        self.assertEqual(
            controller.dscacheutil_addresses(output),
            ([INGRESS_IP], ["2001:db8::1"]),
        )

    def test_unpinned_capture_includes_effective_macos_resolver_answers(self) -> None:
        config = icprlib.load_json_yaml(icprlib.EXAMPLE_CONFIG_PATH)
        effective_ip = "192.0.2.71"
        completed = mock.Mock(
            returncode=0,
            stdout=(
                "name: mask.apple-dns.net\n"
                "ipv6_address: 2001:db8::1\n\n"
                "name: mask.apple-dns.net\n"
                f"ip_address: {effective_ip}\n"
            ),
            stderr="",
        )
        with mock.patch.object(
            controller.subprocess, "run", return_value=completed
        ) as run:
            snapshot, addresses = controller.macos_effective_resolver_snapshot(config)
        self.assertEqual(addresses, [effective_ip])
        self.assertEqual(len(snapshot["lookups"]), 3)
        self.assertEqual(run.call_count, 3)
        for lookup in snapshot["lookups"].values():
            self.assertEqual(lookup["ipv4"], [effective_ip])
            self.assertEqual(lookup["ipv6"], ["2001:db8::1"])

    def test_ipv6_route_parser_accepts_macos_zero_exit_no_route_message(self) -> None:
        completed = mock.Mock(
            returncode=0,
            stdout="",
            stderr="route: writing to routing socket: not in table\n",
        )
        with mock.patch.object(controller.subprocess, "run", return_value=completed):
            status = controller.ipv6_default_route_status()
        self.assertTrue(status["confirmed_absent"])
        self.assertFalse(status["present"])

    def test_absent_networkserviceproxy_is_already_cleared(self) -> None:
        completed = mock.Mock(
            returncode=1,
            stdout="",
            stderr="No matching processes were found\n",
        )
        with mock.patch.object(controller.subprocess, "run", return_value=completed):
            status = controller.clear_networkserviceproxy_state()
        self.assertEqual(status["status"], "already_absent")

    def test_process_running_treats_zombie_as_stopped(self) -> None:
        completed = mock.Mock(returncode=0, stdout="Z+\n")
        with mock.patch.object(controller.os, "kill") as kill:
            with mock.patch.object(controller.subprocess, "run", return_value=completed):
                self.assertFalse(controller.process_running(43372))
        kill.assert_called_once_with(43372, 0)

    def test_process_running_keeps_live_process_running(self) -> None:
        completed = mock.Mock(returncode=0, stdout="S+\n")
        with mock.patch.object(controller.os, "kill") as kill:
            with mock.patch.object(controller.subprocess, "run", return_value=completed):
                self.assertTrue(controller.process_running(43372))
        kill.assert_called_once_with(43372, 0)

    def test_controller_exposes_required_commands(self) -> None:
        parser = controller.parser()
        commands = set()
        for action in parser._actions:  # argparse exposes no public subparser iterator.
            if isinstance(action, argparse._SubParsersAction):
                commands.update(action.choices)
        required = {
            "preflight",
            "prepare-run",
            "finish-run",
            "abort-run",
            "pilot",
            "pair",
            "daily-report",
            "rehearsal-check",
            "cleanup",
        }
        self.assertTrue(required.issubset(commands))


class RecoveryAndGateIntegrityTests(unittest.TestCase):
    def test_reference_gate_accepts_native_headerless_apple_feed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            date = "2026-07-20"
            asn = root / "reference" / "asn" / "origin_prefixes.csv"
            operator = root / "reference" / "asn" / "operator_map_v1.csv"
            feed = root / "feeds" / "apple" / date / "apple-egress.csv"
            write_hashed(asn, "placeholder\n")
            write_hashed(operator, "placeholder\n")
            write_hashed(feed, f"{EGRESS_IP}/32,ZZ,EXAMPLE,Example City,\n")
            config = {
                "mapping": {
                    "origin_asn_file": "reference/asn/origin_prefixes.csv",
                    "operator_map_file": "reference/asn/operator_map_v1.csv",
                }
            }
            with (
                mock.patch.object(controller, "EXPERIMENT_ROOT", root),
                mock.patch.object(
                    controller,
                    "_load_asn_rows",
                    return_value=([{"date": date}], "a" * 64),
                ),
                mock.patch.object(
                    controller,
                    "_load_operator_map",
                    return_value=([], {}, "b" * 64, set()),
                ),
            ):
                self.assertEqual(
                    controller.reference_input_blockers(config, date_utc=date),
                    [],
                )

    def test_pre_capture_abort_is_hash_finalized_without_capture_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            attempt.mkdir()
            icprlib.write_json(
                attempt / "metadata.json",
                {"run_id": "pre-capture-abort", "timeout_deadline_utc": None},
            )
            icprlib.append_jsonl(
                attempt / "events.jsonl",
                {"event": "run_started", "recorded_utc": START},
            )
            self.assertTrue(
                controller.finalize_pre_capture_abort(
                    attempt,
                    reason="operator stopped preparation before capture",
                    condition_changed=False,
                    end_condition_confirmation="conditions remained unchanged",
                )
            )
            self.assertEqual(controller.finalized_attempt_outcome(attempt), "aborted")
            events = [
                json.loads(line)
                for line in (attempt / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(events[-1]["pre_capture_abort"])
            self.assertFalse(events[-1]["capture_started"])
            self.assertFalse((attempt / "capture-state.json").exists())

    def test_pre_capture_abort_refuses_any_privileged_state_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            attempt.mkdir()
            icprlib.write_json(attempt / "metadata.json", {"run_id": "not-pre-capture"})
            icprlib.append_jsonl(
                attempt / "events.jsonl",
                {"event": "run_started", "recorded_utc": START},
            )
            icprlib.write_json(attempt / "dns-pin-state.json", {})
            self.assertFalse(
                controller.finalize_pre_capture_abort(
                    attempt,
                    reason="must not finalize",
                    condition_changed=False,
                    end_condition_confirmation="conditions remained unchanged",
                )
            )
            self.assertFalse((attempt / "manifest.sha256").exists())

    def test_cleanup_can_finalize_a_recovered_prepare_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            attempt.mkdir()
            icprlib.write_json(attempt / "metadata.json", {"run_id": "failed-prepare"})
            icprlib.append_jsonl(
                attempt / "events.jsonl",
                {"event": "run_started", "recorded_utc": START},
            )
            icprlib.append_jsonl(
                attempt / "events.jsonl",
                {
                    "event": "prepare_error_detected",
                    "recorded_utc": END,
                    "reason": "synthetic DNS activation failure",
                    "recovery_required": True,
                },
            )
            self.assertTrue(
                controller.finalize_recovered_prepare_error(
                    attempt, ["previous DNS resolver state restored"]
                )
            )
            self.assertEqual(controller.finalized_attempt_outcome(attempt), "prepare_error")

    def test_malformed_recovery_states_are_aggregated_without_privilege(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            (attempt / "capture.pid").write_text("9999\n", encoding="utf-8")
            (attempt / "capture-state.json").write_text("[]\n", encoding="utf-8")
            (attempt / "dns-pin-state.json").write_text("[]\n", encoding="utf-8")
            (attempt / "firewall-state.json").write_text("[]\n", encoding="utf-8")
            with mock.patch.object(controller, "sudo_ready") as sudo_ready:
                with self.assertRaises(icprlib.IcprError) as context:
                    controller.cleanup_attempt(attempt, {})
            message = str(context.exception)
            self.assertIn("capture cleanup failed", message)
            self.assertIn("DNS cleanup failed", message)
            self.assertIn("PF cleanup failed", message)
            sudo_ready.assert_not_called()

    def test_malformed_partial_dns_restoration_is_rejected_before_privilege(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            path_text = "/etc/resolver/mask.icloud.com"
            icprlib.write_json(
                attempt / "dns-pin-state.json",
                {
                    "resolver_previous": {path_text: {"existed": False}},
                    "resolver_applied": {path_text: "nameserver 127.0.0.1\n"},
                    "resolver_restored": [],
                },
            )
            with mock.patch.object(controller, "sudo_ready") as sudo_ready:
                with self.assertRaisesRegex(
                    icprlib.IcprError, "resolver_restored state is not an object"
                ):
                    controller.cleanup_attempt(attempt, {})
            sudo_ready.assert_not_called()

    def test_restored_timestamp_does_not_bypass_state_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            icprlib.write_json(
                attempt / "dns-pin-state.json",
                {
                    "restored_utc": "2026-07-17T12:00:00Z",
                    "resolver_previous": [],
                    "resolver_applied": {},
                },
            )
            icprlib.write_json(
                attempt / "firewall-state.json",
                {
                    "restored_utc": "2026-07-17T12:00:00Z",
                    "anchor": controller.ALLOWED_PF_ANCHOR,
                    "pf_was_enabled": True,
                },
            )
            with mock.patch.object(controller, "sudo_ready") as sudo_ready:
                with self.assertRaises(icprlib.IcprError) as context:
                    controller.cleanup_attempt(attempt, {})
            message = str(context.exception)
            self.assertIn("DNS state lacks resolver snapshots", message)
            self.assertIn("PF restored state lacks a rules-cleared timestamp", message)
            sudo_ready.assert_not_called()

    def test_read_only_runtime_status_handles_non_object_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempt = root / "client" / "2026-07-17" / "broken"
            attempt.mkdir(parents=True)
            (attempt / "capture-state.json").write_text("[]\n", encoding="utf-8")
            with mock.patch.object(controller, "EXPERIMENT_ROOT", root):
                statuses = controller.attempt_runtime_statuses()
            self.assertEqual(len(statuses), 1)
            self.assertTrue(statuses[0]["recovery_required"])
            self.assertTrue(
                any("capture state is unreadable" in issue for issue in statuses[0]["issues"])
            )

    def test_status_marker_requires_sidecar_and_all_true_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            marker = root / "synthetic-tests-v1.json"
            document = {
                "schema_version": "v1",
                "document_type": "synthetic_tests",
                "status": "passed",
                "recorded_utc": "2026-07-17T12:00:00Z",
                "controller_sha256": controller.controller_sha256(),
                "config_sha256": icprlib.sha256_file(config),
                "checks": {"synthetic_suite_passed": True},
            }
            icprlib.write_json(marker, document)
            icprlib.write_sidecar(marker)
            valid, problem = controller.validate_status_document(
                marker,
                document_type="synthetic_tests",
                expected_status="passed",
                config_hash=icprlib.sha256_file(config),
            )
            self.assertIsNotNone(valid)
            self.assertIsNone(problem)

            marker.chmod(0o640)
            document["checks"]["synthetic_suite_passed"] = False
            icprlib.write_json(marker, document)
            invalid, problem = controller.validate_status_document(
                marker,
                document_type="synthetic_tests",
                expected_status="passed",
                config_hash=icprlib.sha256_file(config),
            )
            self.assertIsNone(invalid)
            self.assertIn("SHA-256 mismatch", str(problem))

            icprlib.write_sidecar(marker)
            invalid, problem = controller.validate_status_document(
                marker,
                document_type="synthetic_tests",
                expected_status="passed",
                config_hash=icprlib.sha256_file(config),
            )
            self.assertIsNone(invalid)
            self.assertIn("checks are not all true", str(problem))

    def test_execution_plan_rejects_duplicate_slot_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            reference_inputs = {
                "apple_egress_feed": {"path": "feeds/apple/test.csv", "sha256": "a" * 64}
            }
            slot = {
                "slot_id": "slot-1",
                "sequence_number": 1,
                "block_id": "unpinned-mgl",
                "attempt_number": 1,
                "session": "daytime",
                "private_relay_state": "on",
                "location_setting": "maintain_general_location",
                "ingress_group": "unpinned",
                "ingress_ip": None,
                "freshness_method": "A",
                "fallback": False,
            }
            plan = {
                "schema_version": "v1",
                "document_type": "rehearsal_execution_plan",
                "status": "frozen",
                "run_mode": "rehearsal",
                "created_utc": "2026-07-17T12:00:00Z",
                "date_utc": "2026-07-17",
                "config_sha256": icprlib.sha256_file(config),
                "controller_sha256": "b" * 64,
                "pin_list_sha256": "c" * 64,
                "reference_inputs": reference_inputs,
                "campaign": "rehearsal-test",
                "session": "daytime",
                "maximum_attempts_per_slot": 2,
                "slots": [slot],
            }
            plan_path = root / "plan.json"
            icprlib.write_json(plan_path, plan)
            icprlib.write_sidecar(plan_path)
            with mock.patch.object(controller, "controller_sha256", return_value="b" * 64), mock.patch.object(
                controller, "reference_input_hashes", return_value=reference_inputs
            ):
                loaded, digest = controller.load_execution_plan(str(plan_path), config)
            self.assertEqual(loaded["slots"][0]["slot_id"], "slot-1")
            self.assertEqual(digest, icprlib.sha256_file(plan_path))

            duplicate = dict(slot)
            duplicate["sequence_number"] = 2
            plan["slots"].append(duplicate)
            icprlib.write_json(plan_path, plan)
            icprlib.write_sidecar(plan_path)
            with mock.patch.object(controller, "controller_sha256", return_value="b" * 64), mock.patch.object(
                controller, "reference_input_hashes", return_value=reference_inputs
            ):
                with self.assertRaisesRegex(icprlib.IcprError, "duplicate slot IDs"):
                    controller.load_execution_plan(str(plan_path), config)

    def test_dated_asn_gaps_reports_distinct_addresses_by_date(self) -> None:
        rows = [
            {
                "run_id": "pending-1",
                "apple_feed_date": "2026-07-25",
                "pending_reason": "dated_asn_mapping_missing",
                "observed_ingress_ip": "192.0.2.1",
                "server_remote_ip": "198.51.100.42",
            },
            {
                "run_id": "pending-2",
                "apple_feed_date": "2026-07-25",
                "pending_reason": "dated_asn_mapping_missing",
                "observed_ingress_ip": "192.0.2.1",
                "server_remote_ip": "198.51.100.43",
            },
            {
                "run_id": "accepted-1",
                "apple_feed_date": "2026-07-25",
                "pending_reason": "",
                "observed_ingress_ip": "192.0.2.2",
                "server_remote_ip": "198.51.100.44",
            },
        ]
        report = controller.dated_asn_gaps(rows, "2026-07-25")
        self.assertEqual(report["status"], "gaps")
        self.assertEqual(report["pending_observations"], 2)
        self.assertEqual(
            report["days"]["2026-07-25"]["observed_ingress_ipv4"],
            ["192.0.2.1"],
        )
        self.assertEqual(
            report["days"]["2026-07-25"]["server_egress_ipv4"],
            ["198.51.100.42", "198.51.100.43"],
        )

    def test_dated_asn_gaps_is_ready_when_filter_has_no_pending_rows(self) -> None:
        rows = [
            {
                "run_id": "pending-other-day",
                "apple_feed_date": "2026-07-24",
                "pending_reason": "dated_asn_mapping_missing",
                "observed_ingress_ip": "192.0.2.1",
                "server_remote_ip": "198.51.100.42",
            }
        ]
        report = controller.dated_asn_gaps(rows, "2026-07-25")
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["pending_observations"], 0)
        self.assertEqual(report["days"], {})

    def test_daily_report_includes_strict_and_objective_specific_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            strict = root / "derived" / "daily_summary_v1.json"
            objective = root / "derived" / "objective_eligibility_summary_v1.json"
            write_hashed(
                strict,
                json.dumps(
                    {
                        "pipeline_version": "v-test",
                        "days": {
                            "2026-07-25": {
                                "attempt_counts": {"attempts": 36, "accepted": 11}
                            }
                        },
                    }
                ),
            )
            write_hashed(
                objective,
                json.dumps(
                    {
                        "days": {
                            "2026-07-25": {
                                "eligibility": {
                                    "objective_1_destination_eligible": {"eligible": 36}
                                }
                            }
                        }
                    }
                ),
            )
            args = argparse.Namespace(date="2026-07-25")
            with mock.patch.object(controller, "EXPERIMENT_ROOT", root), mock.patch(
                "builtins.print"
            ) as output:
                self.assertEqual(controller.cmd_daily_report(args), 0)
            report = json.loads(output.call_args.args[0])
            self.assertEqual(report["strict_pairing"]["attempt_counts"]["accepted"], 11)
            self.assertEqual(
                report["objective_eligibility"]["eligibility"]
                ["objective_1_destination_eligible"]["eligible"],
                36,
            )


def shutil_copytree(source: Path, destination: Path) -> None:
    import shutil

    shutil.copytree(source, destination)


if __name__ == "__main__":
    unittest.main()
