from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = DIAGNOSTIC_ROOT.parent
sys.path.insert(0, str(DIAGNOSTIC_ROOT))
sys.path.insert(0, str(REPO_ROOT / "experiment"))

import platform_ops
import protocol_diag
from icprlib import write_json, write_sidecar


class FrozenDesignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config, self.config_hash = protocol_diag.load_configuration(
            DIAGNOSTIC_ROOT / "examples" / "dual-protocol-config.json"
        )
        self.plan, _ = protocol_diag.load_plan(
            DIAGNOSTIC_ROOT / "examples" / "dual-protocol-plan.json",
            self.config_hash,
        )

    def test_exact_ten_slot_alternation(self) -> None:
        self.assertEqual(len(self.plan["slots"]), 10)
        self.assertEqual(
            [slot["condition"] for slot in self.plan["slots"]],
            ["udp_permitted", "udp_blocked"] * 5,
        )

    def test_diagnostic_is_outside_campaign_client_root(self) -> None:
        diagnostic = (DIAGNOSTIC_ROOT / "client").resolve()
        campaign = (REPO_ROOT / "experiment" / "client").resolve()
        self.assertNotEqual(diagnostic, campaign)
        self.assertNotIn(campaign, diagnostic.parents)

    def test_campaign_gate_accepts_verified_completion_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pull = root / "pull-receipt.txt"
            pairs = root / "pairs.csv"
            pull.write_text("verified archive pull\n", encoding="utf-8")
            pairs.write_text(
                "run_id,disposition,pending_reason\n"
                "synthetic-run,accepted,\n",
                encoding="utf-8",
            )
            attestation = {
                "schema_version": 1,
                "document_type": (
                    "icpr_protocol_diagnostic_campaign_completion_attestation"
                ),
                "status": "verified",
                "completed_campaign_days": 14,
                "campaign_end_date_utc": "2000-01-14",
                "last_campaign_attempt_utc": "2000-01-14T11:00:00Z",
                "post_campaign_pull_utc": "2000-01-15T04:00:00Z",
                "backup_verified": True,
                "post_campaign_pull_path": pull.name,
                "post_campaign_pull_sha256": protocol_diag.sha256_file(pull),
                "final_pairing_command": (
                    "./experiment/icpr pair --server-root server/recovery-data"
                ),
                "final_pairs_path": pairs.name,
                "final_pairs_sha256": protocol_diag.sha256_file(pairs),
                "final_pending_mappings": 0,
                "final_dated_asn_gaps": 0,
                "dated_asn_gap_report_path": pairs.name,
                "dated_asn_gap_report_sha256": protocol_diag.sha256_file(pairs),
            }
            attestation_path = root / "completion.json"
            write_json(attestation_path, attestation)
            write_sidecar(attestation_path)
            config = json.loads(json.dumps(self.config))
            config["campaign_completion_gate"]["attestation_path"] = (
                attestation_path.name
            )
            with mock.patch.object(protocol_diag, "REPO_ROOT", root):
                report = protocol_diag.verify_campaign_completion(config)
            self.assertTrue(report["ready"], report["blockers"])
            self.assertEqual(
                report["attestation_sha256"],
                protocol_diag.sha256_file(attestation_path),
            )

    def test_candidate_snapshot_requires_pin_origin_and_canonical_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.json"
            value = {
                "document_type": "icpr_protocol_diagnostic_dns_candidate_snapshot",
                "recorded_utc": "2026-08-04T01:00:00Z",
                "capture_candidates": ["192.0.2.10", "192.0.2.20"],
                "candidate_hostname_map": {
                    "192.0.2.10": ["measurement.example.org"],
                    "192.0.2.20": ["mask-h2.icloud.com", "mask.icloud.com"],
                },
                "fallback_candidate_ipv4": ["192.0.2.20"],
            }
            write_json(path, value)
            write_sidecar(path)
            loaded, digest = protocol_diag.verify_candidate_snapshot(
                path, self.config, require_run_day=False
            )
            self.assertEqual(loaded, value)
            self.assertEqual(len(digest), 64)

    def test_pair_subcommand_defaults_remain_isolated(self) -> None:
        args = protocol_diag.parser().parse_args(["pair"])
        self.assertEqual(
            Path(args.client_root).resolve(),
            (DIAGNOSTIC_ROOT / "client").resolve(),
        )
        self.assertEqual(
            Path(args.derived_root).resolve(),
            (DIAGNOSTIC_ROOT / "derived").resolve(),
        )
        self.assertFalse(hasattr(args, "feed_root"))

    def test_server_snapshot_subcommand_requires_explicit_purpose(self) -> None:
        args = protocol_diag.parser().parse_args(
            [
                "snapshot-server-caddy",
                "--purpose",
                "readiness",
                "--required-run-id",
                "readiness-1",
            ]
        )
        self.assertEqual(args.purpose, "readiness")
        self.assertEqual(args.required_run_id, ["readiness-1"])

    def test_complete_caddy_prefix_validation_is_nonselective(self) -> None:
        content = (
            b'{"run_id":"other"}\n'
            b'{"run_id":"readiness-1","request":{"uri":"/probe/readiness-1"}}\n'
        )
        rows, counts = protocol_diag._validate_caddy_prefix_content(
            content, ["readiness-1"], "readiness"
        )
        self.assertEqual(rows, 2)
        self.assertEqual(counts, {"readiness-1": 1})
        with self.assertRaises(Exception):
            protocol_diag._validate_caddy_prefix_content(
                content.rstrip(b"\n"), ["readiness-1"], "readiness"
            )

    def test_caddy_prefix_provenance_binds_exact_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            caddy_path = root / "server/recovery-data/live-caddy-prefixes/s/access-prefix.jsonl"
            caddy_path.parent.mkdir(parents=True)
            caddy_path.write_text('{"run_id":"r"}\n', encoding="utf-8")
            write_sidecar(caddy_path)
            digest = protocol_diag.sha256_file(caddy_path)
            provenance_path = caddy_path.parent / "snapshot-provenance.json"
            provenance = {
                "schema_version": 1,
                "document_type": "icpr_live_caddy_prefix_snapshot",
                "status": "verified",
                "capture_method": "nonselective_active_log_byte_prefix_v1",
                "source_nonselective_prefix": True,
                "source_mutated": False,
                "snapshot_path": str(caddy_path.relative_to(root)),
                "snapshot_sha256": digest,
                "prefix_bytes": caddy_path.stat().st_size,
                "source_stat_before": {"device": 1, "inode": 2, "size_bytes": 0},
                "source_stat_after": {
                    "device": 1,
                    "inode": 2,
                    "size_bytes": caddy_path.stat().st_size,
                },
            }
            write_json(provenance_path, provenance)
            write_sidecar(provenance_path)
            with mock.patch.object(protocol_diag, "REPO_ROOT", root):
                loaded = protocol_diag.verify_caddy_snapshot_provenance(
                    provenance_path, caddy_path, digest
                )
            self.assertEqual(loaded["snapshot_sha256"], digest)

    def test_operator_cannot_supply_controller_detected_retry_codes(self) -> None:
        root = protocol_diag.parser()
        abort_parser = next(
            action.choices["abort-run"]
            for action in root._actions
            if getattr(action, "choices", None) and "abort-run" in action.choices
        )
        mechanical_action = next(
            action for action in abort_parser._actions if action.dest == "mechanical_failure_code"
        )
        self.assertEqual(mechanical_action.choices, ["RESPONSE_EVIDENCE_NOT_SAVED"])
        finish_parser = next(
            action.choices["finish-run"]
            for action in root._actions
            if getattr(action, "choices", None) and "finish-run" in action.choices
        )
        outcome_action = next(
            action for action in finish_parser._actions if action.dest == "outcome"
        )
        self.assertNotIn("mechanical_failure", outcome_action.choices)
        self.assertIn("CAPTURE_RUNTIME_FAILED", self.config["retry_policy"]["allowed_only_for_codes"])

    def test_unauthorized_mechanical_failure_consumes_the_planned_slot(self) -> None:
        attempts = [
            (
                Path("/tmp/example"),
                {"retry_number": 1},
                {
                    "outcome": "prepare_error",
                    "retry_authorized": False,
                },
            )
        ]
        self.assertTrue(protocol_diag.slot_complete(attempts, maximum=2))

    def test_finish_attempt_cleans_up_before_reporting_unknown_analysis_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            stop_watchdog = mock.Mock()
            cleanup_attempt = mock.Mock(return_value=[])
            with (
                mock.patch.object(
                    protocol_diag,
                    "RUNTIME_ROOT",
                    Path(temporary) / "runtime",
                ),
                mock.patch.object(
                    protocol_diag,
                    "attempt_metadata",
                    return_value={"analysis_family": "retired_probe_family"},
                ),
                mock.patch.object(
                    protocol_diag,
                    "get_profile_for_analysis_family",
                    side_effect=ValueError("unknown diagnostic analysis family: retired_probe_family"),
                ),
                mock.patch.object(protocol_diag, "stop_watchdog", stop_watchdog),
                mock.patch.object(protocol_diag, "cleanup_attempt", cleanup_attempt),
            ):
                with self.assertRaisesRegex(
                    protocol_diag.IcprError,
                    "unknown diagnostic analysis family: retired_probe_family",
                ):
                    protocol_diag.finish_attempt(
                        attempt,
                        outcome="timeout",
                        reason="test",
                        response_file=None,
                        mechanical_failure_code=None,
                        condition_changed=False,
                        end_confirmation="test",
                    )
            stop_watchdog.assert_called_once_with(attempt)
            cleanup_attempt.assert_called_once_with(attempt)

    def test_bypass_and_condition_change_latch_safety_stop(self) -> None:
        grouped = {
            "slot": [
                (
                    Path("/tmp/bypass"),
                    {},
                    {"outcome": "direct_bypass", "condition_changed": True},
                )
            ]
        }
        reasons = protocol_diag.safety_stop_reasons(grouped)
        self.assertEqual(len(reasons), 2)

    def test_manifest_verified_response_bypass_latches_after_recovery_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            (attempt / "response.json").write_text(
                json.dumps({"remote_ip": "192.0.2.44"}), encoding="utf-8"
            )
            grouped = {
                "slot": [
                    (
                        attempt,
                        {"real_public_ipv4": "192.0.2.44"},
                        {"outcome": "prepare_error", "condition_changed": False},
                    )
                ]
            }
            reasons = protocol_diag.safety_stop_reasons(grouped)
            self.assertEqual(len(reasons), 1)
            self.assertIn("bypass", reasons[0])

    def test_explicit_safety_stop_code_latches(self) -> None:
        grouped = {
            "slot": [
                (
                    Path("/tmp/safety"),
                    {},
                    {
                        "outcome": "aborted",
                        "condition_changed": False,
                        "safety_stop_code": "SERVER_EVIDENCE_UNAVAILABLE",
                    },
                )
            ]
        }
        reasons = protocol_diag.safety_stop_reasons(grouped)
        self.assertEqual(len(reasons), 1)
        self.assertIn("SERVER_EVIDENCE_UNAVAILABLE", reasons[0])

    def test_global_controller_lock_is_non_reentrant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(protocol_diag, "RUNTIME_ROOT", Path(temporary)):
                first = protocol_diag.acquire_global_lock()
                try:
                    with self.assertRaises(Exception):
                        protocol_diag.acquire_global_lock()
                finally:
                    protocol_diag.release_lock(first)


class ScopedMechanismTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config, _ = protocol_diag.load_configuration(
            DIAGNOSTIC_ROOT / "examples" / "dual-protocol-config.json"
        )

    def test_hosts_override_is_byte_preserving(self) -> None:
        baseline = b"127.0.0.1 localhost"  # deliberately no final newline
        applied = platform_ops.render_hosts_override(
            baseline,
            "mask.apple-dns.net",
            "192.0.2.20",
            "icpr-protocol-diagnostic-v1 temporary",
        )
        self.assertTrue(applied.startswith(baseline + b"\n"))
        self.assertEqual(applied.count(b"mask.apple-dns.net"), 1)
        with self.assertRaises(Exception):
            platform_ops.render_hosts_override(
                applied,
                "mask.apple-dns.net",
                "192.0.2.20",
                "icpr-protocol-diagnostic-v1 temporary",
            )

    def test_hosts_override_can_pin_all_frozen_private_relay_names(self) -> None:
        baseline = b"127.0.0.1 localhost\n"
        names = [
            "mask.apple-dns.net",
            "mask.icloud.com",
            "mask-h2.icloud.com",
        ]
        applied = platform_ops.render_hosts_override(
            baseline, names, "192.0.2.20", "temporary"
        )
        expected_line = (
            "192.0.2.20\tmask.apple-dns.net mask.icloud.com "
            "mask-h2.icloud.com\t# temporary"
        )
        for name in names:
            self.assertEqual(
                platform_ops.hosts_target_entries(applied, name),
                [{"line_number": 2, "address": "192.0.2.20", "line": expected_line}],
            )

    def test_capture_filter_is_exact_host_and_443_scope(self) -> None:
        rendered = platform_ops.capture_filter(
            ["192.0.2.20", "192.0.2.10", "192.0.2.21"]
        )
        self.assertEqual(
            rendered,
            "(host 192.0.2.10 or host 192.0.2.20 or host 192.0.2.21) "
            "and (tcp port 443 or udp port 443)",
        )
        self.assertNotIn("port 53", rendered)

    def test_pf_rule_is_single_ingress_udp_only(self) -> None:
        rule = platform_ops.render_pf_rule(self.config, "en0")
        platform_ops.validate_rendered_pf_rule(rule, self.config, "en0")
        self.assertIn("proto udp", rule)
        self.assertIn("to 192.0.2.20 port = 443", rule)
        self.assertNotIn("proto tcp", rule)
        self.assertNotIn("192.0.2.10", rule)

    def test_pf_system_parser_is_privileged_but_non_mutating(self) -> None:
        rule = platform_ops.render_pf_rule(self.config, "en0")
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "/sbin/pfctl", "-vnf", "-"], 0, "parsed", ""
        )
        with (
            mock.patch.object(platform_ops, "sudo_ready") as ready,
            mock.patch.object(platform_ops.subprocess, "run", return_value=completed) as run,
        ):
            result = platform_ops.system_validate_pf_rule(rule)
        ready.assert_called_once_with()
        self.assertEqual(
            run.call_args.args[0], ["sudo", "-n", "/sbin/pfctl", "-vnf", "-"]
        )
        self.assertTrue(result["valid"])

    def test_pf_counter_parser(self) -> None:
        snapshot = "Evaluations: 12 Packets: 3 Bytes: 360 States: 0"
        self.assertEqual(
            platform_ops.pf_rule_statistics(snapshot),
            {"evaluations": 12, "packets": 3, "bytes": 360, "states": 0},
        )

    def test_dns_cleanup_restores_saved_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            baseline = b"127.0.0.1 localhost\n"
            applied = baseline + b"192.0.2.20\tmask.apple-dns.net\t# temporary\n"
            (attempt / "hosts.baseline").write_bytes(baseline)
            state = {
                "hosts_previous_base64": base64.b64encode(baseline).decode(),
                "hosts_applied_base64": base64.b64encode(applied).decode(),
                "hosts_path": "/etc/hosts",
                "cname_target": "mask.apple-dns.net",
                "hosts_uid": 0,
                "hosts_gid": 0,
                "hosts_mode": "644",
                "hosts_installed_utc": "2026-08-04T01:00:00Z",
            }
            write_json(attempt / "dns-pin-state.json", state)
            current = {"bytes": applied}

            def fake_sudo_bytes(_argv: list[str]) -> bytes:
                return current["bytes"]

            def fake_sudo_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if argv and argv[0] == "/usr/bin/install":
                    current["bytes"] = baseline
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops, "sudo_bytes", side_effect=fake_sudo_bytes),
                mock.patch.object(platform_ops, "sudo_run", side_effect=fake_sudo_run),
                mock.patch.object(
                    platform_ops,
                    "clear_networkserviceproxy_state",
                    return_value={"status": "already_absent"},
                ),
            ):
                action = platform_ops.restore_dns(attempt)
            self.assertIn("byte-for-byte", action or "")
            self.assertEqual(current["bytes"], baseline)
            restored = json.loads((attempt / "dns-pin-state.json").read_text())
            self.assertIn("restored_utc", restored)

    def test_pf_cleanup_clears_only_dedicated_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            loaded = platform_ops.render_pf_rule(self.config, "en0")
            write_json(
                attempt / "firewall-state.json",
                {
                    "anchor": "com.apple/icpr-protocol-diagnostic-v1",
                    "condition": "udp_blocked",
                    "rule_loaded": True,
                    "loaded_rules_snapshot": loaded,
                    "pf_was_enabled": True,
                    "pf_enable_token": "",
                },
            )
            current = {"rules": loaded}

            def fake_sudo_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if argv[-2:] == ["-F", "rules"]:
                    current["rules"] = ""
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[-1:] == ["-sr"]:
                    return subprocess.CompletedProcess(argv, 0, current["rules"], "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops, "sudo_run", side_effect=fake_sudo_run),
            ):
                action = platform_ops.restore_firewall(attempt)
            self.assertIn("anchor cleared", action or "")
            self.assertEqual(current["rules"], "")
            restored = json.loads((attempt / "firewall-state.json").read_text())
            self.assertIn("restored_utc", restored)


if __name__ == "__main__":
    unittest.main()
