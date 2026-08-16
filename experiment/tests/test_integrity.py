from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

import icprlib  # noqa: E402


def valid_example_config() -> dict:
    config = copy.deepcopy(
        icprlib.load_json_yaml(icprlib.EXAMPLE_CONFIG_PATH)
    )
    config["configuration_status"] = "frozen"
    config["freshness"]["selected_method"] = "A"
    config["daily_schedule"]["target_accepted_per_pinned_block"] = 2
    return config


class IntegrityTests(unittest.TestCase):
    def test_alternate_controlled_endpoint_is_accepted(self) -> None:
        config = valid_example_config()
        config["server"]["hostname"] = "alternate.example.net"
        config["server"]["url_template"] = (
            "https://alternate.example.net/probe/{run_id}"
        )

        self.assertEqual(icprlib.configuration_gaps(config), [])

    def test_endpoint_url_must_match_the_configured_hostname(self) -> None:
        config = valid_example_config()
        config["server"]["hostname"] = "alternate.example.net"

        gaps = icprlib.configuration_gaps(config)

        self.assertNotIn("server.hostname must be a valid DNS hostname", gaps)
        self.assertIn(
            "server.url_template must exactly match "
            "https://<server.hostname>/probe/{run_id}",
            gaps,
        )

    def test_invalid_endpoint_hostnames_are_rejected(self) -> None:
        for hostname in (
            "localhost",
            "-probe.example.org",
            "probe..example.org",
            "probe_example.org",
            "probe.example.org/path",
        ):
            with self.subTest(hostname=hostname):
                config = valid_example_config()
                config["server"]["hostname"] = hostname
                config["server"]["url_template"] = (
                    f"https://{hostname}/probe/{{run_id}}"
                )

                self.assertIn(
                    "server.hostname must be a valid DNS hostname",
                    icprlib.configuration_gaps(config),
                )

    def test_sidecar_is_bound_to_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "evidence.txt"
            artifact.write_text("evidence\n", encoding="utf-8")
            sidecar = icprlib.write_sidecar(artifact)
            self.assertEqual(icprlib.verify_sidecar(artifact), icprlib.sha256_file(artifact))
            sidecar.chmod(0o640)
            sidecar.write_text(
                f"{icprlib.sha256_file(artifact)}  different-name.txt\n",
                encoding="utf-8",
            )
            with self.assertRaises(icprlib.IcprError):
                icprlib.verify_sidecar(artifact)

    def test_attempt_manifest_rejects_unlisted_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / "attempt"
            attempt.mkdir()
            (attempt / "metadata.json").write_text("{}\n", encoding="utf-8")
            icprlib.finalize_attempt(attempt)
            attempt.chmod(0o750)
            (attempt / "late-file.txt").write_text("not manifested\n", encoding="utf-8")
            with self.assertRaises(icprlib.IcprError):
                icprlib.verify_attempt(attempt)

    def test_private_pin_file_requires_hash_and_nonoverlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pins = Path(temporary) / "ingress_pins.yaml"
            value = {
                "version": "manual-test-v1",
                "verified_utc": "2026-07-17T08:00:00Z",
                "akamai": ["192.0.2.10"],
                "apple_as714": ["192.0.2.20"],
            }
            pins.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(icprlib.IcprError):
                icprlib.load_pins(pins)
            icprlib.write_sidecar(pins)
            self.assertEqual(icprlib.load_pins(pins)["version"], "manual-test-v1")
            value["apple_as714"] = ["192.0.2.10"]
            pins.write_text(json.dumps(value), encoding="utf-8")
            icprlib.write_sidecar(pins)
            with self.assertRaises(icprlib.IcprError):
                icprlib.load_pins(pins)

    def test_objective_three_wildcards_cannot_freeze(self) -> None:
        config = valid_example_config()
        config["objective_3_ground_truth"].update(
            {
                "true_country_code": "ZZ",
                "true_time_zone": "Etc/UTC",
                "country_time_zone_permitted_apple_locations": [{}],
                "maintain_general_location_boundary": {"boundary_id": "too-broad"},
                "temporal_intersection_rule": {
                    "rule_id": "exact_advertised_field_intersection",
                    "fields": ["country", "region", "city"],
                },
            }
        )
        gaps = icprlib.configuration_gaps(config)
        self.assertTrue(any("non-wildcard" in gap for gap in gaps))
        self.assertTrue(any("allowed country codes" in gap for gap in gaps))


if __name__ == "__main__":
    unittest.main()
