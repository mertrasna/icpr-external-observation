from __future__ import annotations

import copy
import sys
import tempfile
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

try:
    import series_profile
except ModuleNotFoundError:
    series_profile = None

import protocol_diag
import pairing
from icprlib import write_sidecar


class H3RequiredProfileTests(unittest.TestCase):
    def test_h3_profile_keeps_mutable_outputs_out_of_legacy_roots(self) -> None:
        self.assertIsNotNone(series_profile, "series profile module is required")
        profile = series_profile.get_series_profile("h3_required")

        expected_root = DIAGNOSTIC_ROOT / "h3-required"
        self.assertEqual(profile.client_root, expected_root / "client")
        self.assertEqual(profile.derived_root, expected_root / "derived")
        self.assertEqual(profile.reports_root, expected_root / "reports")
        self.assertEqual(profile.runtime_root, expected_root / "runtime")
        self.assertEqual(profile.reference_root, expected_root / "reference")
        self.assertNotEqual(profile.client_root, protocol_diag.CLIENT_ROOT)

    def test_unknown_profile_is_rejected(self) -> None:
        self.assertIsNotNone(series_profile, "series profile module is required")
        with self.assertRaises(ValueError):
            series_profile.get_series_profile("not-a-series")

    def test_legacy_parser_selects_dual_protocol_by_default(self) -> None:
        args = protocol_diag.parser().parse_args(["pair"])
        self.assertTrue(
            hasattr(args, "series_profile"),
            "parser must expose the selected diagnostic series",
        )
        self.assertEqual(args.series_profile, "dual_protocol")

    def test_h3_plan_accepts_only_h3_slot_ids_and_pair_metadata(self) -> None:
        config_hash = "a" * 64
        slots = []
        for index in range(1, 11):
            slots.append(
                {
                    "slot_id": f"h3-required-v1-{index:03d}",
                    "sequence_number": index,
                    "condition": "udp_permitted" if index % 2 else "udp_blocked",
                    "pair_number": (index + 1) // 2,
                    "pair_position": "permitted" if index % 2 else "blocked",
                }
            )
        value = {
            "schema_version": 1,
            "document_type": "icpr_protocol_diagnostic_plan",
            "plan_version": "v1",
            "status": "frozen",
            "configuration_sha256": config_hash,
            "analysis_family": "h3_required",
            "denominator_id": "h3-required-v1",
            "required_destination_protocol": "HTTP/3.0",
            "slots": slots,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            write_sidecar(path)

            try:
                plan, _ = protocol_diag.load_plan(
                    path, config_hash, series_profile="h3_required"
                )
            except TypeError as exc:
                self.fail(f"load_plan lacks H3-required profile validation: {exc}")

        self.assertEqual(plan["slots"], slots)

    def test_h3_parser_resolves_profile_specific_command_defaults(self) -> None:
        profile = series_profile.get_series_profile("h3_required")

        pair_args = protocol_diag.parser().parse_args(
            ["--series-profile", "h3_required", "pair"]
        )
        preflight_args = protocol_diag.parser().parse_args(
            ["--series-profile", "h3_required", "preflight"]
        )
        gate_args = protocol_diag.parser().parse_args(
            [
                "--series-profile",
                "h3_required",
                "gate-status",
                "--session-id",
                "20260804T100000Z-a1b2c3d4",
            ]
        )

        self.assertEqual(Path(pair_args.client_root), profile.client_root)
        self.assertEqual(Path(pair_args.derived_root), profile.derived_root)
        self.assertEqual(Path(pair_args.config), profile.config_path)
        self.assertEqual(Path(preflight_args.config), profile.config_path)
        self.assertEqual(Path(preflight_args.plan), profile.plan_path)
        self.assertEqual(Path(gate_args.config), profile.config_path)
        self.assertEqual(pair_args.runtime_root, profile.runtime_root)
        self.assertEqual(pair_args.reference_root, profile.reference_root)

    def test_activating_h3_profile_retargets_all_controller_mutable_roots(self) -> None:
        legacy = series_profile.get_series_profile("dual_protocol")
        h3 = series_profile.get_series_profile("h3_required")
        self.assertTrue(
            hasattr(protocol_diag, "activate_series_profile"),
            "controller must activate the selected profile before dispatch",
        )
        try:
            protocol_diag.activate_series_profile(h3)
            self.assertEqual(protocol_diag.CLIENT_ROOT, h3.client_root)
            self.assertEqual(protocol_diag.REFERENCE_ROOT, h3.reference_root)
            self.assertEqual(protocol_diag.RUNTIME_ROOT, h3.runtime_root)
            self.assertEqual(protocol_diag.ACTIVE_SERIES_PROFILE, "h3_required")
        finally:
            if hasattr(protocol_diag, "activate_series_profile"):
                protocol_diag.activate_series_profile(legacy)

    def test_frozen_h3_artifacts_load_as_exact_five_pair_series(self) -> None:
        profile = series_profile.get_series_profile("h3_required")
        self.assertTrue(profile.config_path.is_file(), "frozen H3 config is absent")
        self.assertTrue(profile.plan_path.is_file(), "frozen H3 plan is absent")

        config, config_hash = protocol_diag.load_configuration(profile.config_path)
        plan, _ = protocol_diag.load_plan(
            profile.plan_path,
            config_hash,
            series_profile="h3_required",
        )

        self.assertEqual(config["analysis_family"], "h3_required")
        self.assertEqual(plan["denominator_id"], "h3-required-v1")
        self.assertEqual(
            [slot["pair_number"] for slot in plan["slots"]],
            [1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
        )

    def test_dedicated_wrapper_dispatches_without_live_side_effects(self) -> None:
        wrapper = DIAGNOSTIC_ROOT / "h3-required-diag"
        self.assertTrue(wrapper.is_file(), "dedicated H3 wrapper is absent")
        completed = subprocess.run(
            [str(wrapper), "pair", "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("protocol_diag.py pair", completed.stdout)

    def test_pairer_writes_only_to_explicit_profile_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client_root = root / "client"
            derived_root = root / "derived"
            client_root.mkdir()
            with mock.patch.object(pairing, "load_caddy_records", return_value=([], [])):
                try:
                    report = pairing.run(
                        client_root=client_root,
                        server_root=pairing.DEFAULT_SERVER_ROOT,
                        derived_root=derived_root,
                        server_private_ip="10.0.0.10",
                        allowed_client_root=client_root,
                        allowed_derived_root=derived_root,
                        analysis_family="h3_required",
                    )
                except TypeError as exc:
                    self.fail(f"pairer lacks explicit profile-root binding: {exc}")

            self.assertEqual(report["attempts"], 0)
            self.assertEqual(report["analysis_family"], "h3_required")
            self.assertTrue((derived_root / "trial-results.json").is_file())

    def test_direct_pairing_cli_requires_explicit_private_ipv4(self) -> None:
        parser = pairing.build_parser()
        private_ip_action = next(
            action
            for action in parser._actions
            if action.dest == "server_private_ipv4"
        )
        self.assertTrue(private_ip_action.required)
        args = parser.parse_args(
            ["--server-private-ipv4", "10.0.0.10"]
        )
        self.assertEqual(args.server_private_ipv4, "10.0.0.10")

    def test_controller_pairing_policy_binds_selected_profile_roots(self) -> None:
        self.assertTrue(
            hasattr(protocol_diag, "pairing_policy"),
            "controller must bind pairer roots to the selected profile",
        )
        args = protocol_diag.parser().parse_args(
            ["--series-profile", "h3_required", "pair"]
        )
        policy = protocol_diag.pairing_policy(args)
        profile = series_profile.get_series_profile("h3_required")

        self.assertEqual(policy["allowed_client_root"], profile.client_root)
        self.assertEqual(policy["allowed_derived_root"], profile.derived_root)
        self.assertEqual(policy["analysis_family"], "h3_required")

    def test_hash_verified_config_binds_alternate_gate_host_and_private_ip(self) -> None:
        profile = series_profile.get_series_profile("h3_required")
        value = copy.deepcopy(json.loads(profile.config_path.read_text(encoding="utf-8")))
        value["server"]["private_ipv4"] = "10.0.0.10"
        value["server"]["live_caddy_snapshot"]["ssh_target"] = (
            "researcher@gate.example.org"
        )
        value["origin_gate"]["private_ipv4"] = "10.0.0.10"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "configuration.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            write_sidecar(path)

            loaded, _ = protocol_diag.load_configuration(path)
            client = protocol_diag._gate_client_for_key("/tmp/test-key", loaded)

        self.assertEqual(client.host, "researcher@gate.example.org")
        self.assertEqual(client.policy.private_ipv4, "10.0.0.10")

    def test_hash_verified_config_rejects_origin_gate_server_ip_mismatch(self) -> None:
        profile = series_profile.get_series_profile("h3_required")
        value = copy.deepcopy(json.loads(profile.config_path.read_text(encoding="utf-8")))
        value["server"]["private_ipv4"] = "10.0.0.10"
        value["origin_gate"]["private_ipv4"] = "10.0.0.11"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "configuration.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            write_sidecar(path)

            with self.assertRaises(protocol_diag.IcprError):
                protocol_diag.load_configuration(path)

    def test_hash_verified_config_rejects_public_server_and_gate_ip(self) -> None:
        profile = series_profile.get_series_profile("h3_required")
        value = copy.deepcopy(json.loads(profile.config_path.read_text(encoding="utf-8")))
        value["server"]["private_ipv4"] = "8.8.8.8"
        value["origin_gate"]["private_ipv4"] = "8.8.8.8"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "configuration.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            write_sidecar(path)

            with self.assertRaises(protocol_diag.IcprError):
                protocol_diag.load_configuration(path)


if __name__ == "__main__":
    unittest.main()
