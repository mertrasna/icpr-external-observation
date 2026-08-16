#!/usr/bin/env python3
"""Check the frozen files needed by the two documented diagnostic profiles."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
DIAGNOSTIC_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DIAGNOSTIC_ROOT))

import series_profile  # noqa: E402

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

PUBLIC_PROFILES = (
    {
        "name": "dual protocol",
        "config": Path("protocol-diagnostic/examples/dual-protocol-config.json"),
        "plan": Path("protocol-diagnostic/examples/dual-protocol-plan.json"),
        "slot_prefix": "protocol-v2-",
    },
    {
        "name": "H3 required",
        "config": Path("protocol-diagnostic/examples/h3-required-config.json"),
        "plan": Path("protocol-diagnostic/examples/h3-required-plan.json"),
        "slot_prefix": "h3-required-v1-",
    },
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class PublicProfileFilesTests(unittest.TestCase):
    def test_only_complete_profiles_are_advertised(self) -> None:
        self.assertEqual(
            series_profile.series_profile_names(),
            ("dual_protocol", "h3_required"),
        )

    def load_verified_json(self, relative_path: Path) -> tuple[dict, str]:
        path = REPOSITORY / relative_path
        self.assertTrue(path.is_file(), f"missing public file: {relative_path}")

        sidecar = path.with_name(path.name + ".sha256")
        self.assertTrue(
            sidecar.is_file(),
            f"missing SHA-256 sidecar: {sidecar.relative_to(REPOSITORY)}",
        )

        rows = [row for row in sidecar.read_text(encoding="utf-8").splitlines() if row]
        self.assertEqual(len(rows), 1, f"{sidecar} must contain exactly one hash row")
        fields = rows[0].split()
        self.assertEqual(len(fields), 2, f"malformed SHA-256 sidecar: {sidecar}")
        expected_digest, recorded_name = fields
        self.assertRegex(expected_digest, SHA256_RE)
        self.assertEqual(recorded_name.lstrip("*"), path.name)

        actual_digest = sha256_file(path)
        self.assertEqual(expected_digest, actual_digest, f"hash mismatch for {path}")

        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(document, dict, f"{path} must contain a JSON object")
        return document, actual_digest

    def test_advertised_profiles_are_complete_and_consistent(self) -> None:
        for profile in PUBLIC_PROFILES:
            with self.subTest(profile=profile["name"]):
                config, config_digest = self.load_verified_json(profile["config"])
                plan, _ = self.load_verified_json(profile["plan"])

                self.assertEqual(
                    config.get("document_type"),
                    "icpr_protocol_diagnostic_configuration",
                )
                self.assertEqual(
                    plan.get("document_type"), "icpr_protocol_diagnostic_plan"
                )
                self.assertEqual(config.get("status"), "frozen")
                self.assertEqual(plan.get("status"), "frozen")
                self.assertEqual(plan.get("diagnostic_id"), config.get("diagnostic_id"))
                self.assertEqual(
                    plan.get("configuration_path"), profile["config"].as_posix()
                )
                self.assertEqual(plan.get("configuration_sha256"), config_digest)

                slots = plan.get("slots")
                self.assertIsInstance(slots, list)
                self.assertEqual(plan.get("planned_observations"), len(slots))
                self.assertEqual(len(slots), 10)
                self.assertEqual(
                    [slot.get("sequence_number") for slot in slots],
                    list(range(1, len(slots) + 1)),
                )

                slot_ids = [slot.get("slot_id") for slot in slots]
                self.assertEqual(len(slot_ids), len(set(slot_ids)))
                self.assertTrue(
                    all(
                        isinstance(slot_id, str)
                        and slot_id.startswith(profile["slot_prefix"])
                        for slot_id in slot_ids
                    )
                )
                self.assertEqual(
                    [slot.get("condition") for slot in slots],
                    ["udp_permitted", "udp_blocked"] * 5,
                )


if __name__ == "__main__":
    unittest.main()
