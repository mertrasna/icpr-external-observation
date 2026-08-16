"""Offline tests for the controlled-server installer interface."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parents[1]
INSTALLER = SERVER_DIR / "install.sh"
CADDY_TEMPLATE = SERVER_DIR / "Caddyfile"
PLACEHOLDER = "__ICPR_HOSTNAME__"


class InstallerHostnameTests(unittest.TestCase):
    def run_function(
        self, function: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        command = f'source "$1"; {function} "$2"'
        return subprocess.run(
            ["bash", "-c", command, "bash", str(INSTALLER), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_lowercase_fully_qualified_dns_names(self) -> None:
        for hostname in (
            "measurement.example.org",
            "a-b.example",
            "xn--bcher-kva.example",
        ):
            with self.subTest(hostname=hostname):
                result = self.run_function("validate_hostname", hostname)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unsafe_or_ambiguous_hostnames(self) -> None:
        too_long_label = f"{'a' * 64}.example"
        for hostname in (
            "",
            "localhost",
            "Measurement.example.org",
            "-probe.example.org",
            "probe-.example.org",
            "probe_name.example.org",
            "probe..example.org",
            "probe.example.org.",
            "https://probe.example.org",
            "probe.example.org:443",
            "*.example.org",
            "192.0.2.1",
            too_long_label,
        ):
            with self.subTest(hostname=hostname):
                result = self.run_function("validate_hostname", hostname)
                self.assertNotEqual(result.returncode, 0)

    def test_render_uses_hostname_once_and_does_not_change_template(self) -> None:
        original = CADDY_TEMPLATE.read_bytes()
        self.assertEqual(original.decode().count(PLACEHOLDER), 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            rendered_path = Path(temp_dir) / "Caddyfile"
            command = (
                'source "$1"; validate_hostname "$2"; '
                'render_caddy_configuration "$2" "$3"'
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    command,
                    "bash",
                    str(INSTALLER),
                    "measurement.example.org",
                    str(rendered_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = rendered_path.read_text()
            self.assertNotIn(PLACEHOLDER, rendered)
            self.assertEqual(rendered.count("measurement.example.org"), 1)

        self.assertEqual(CADDY_TEMPLATE.read_bytes(), original)

    def test_render_refuses_to_overwrite_template(self) -> None:
        original = CADDY_TEMPLATE.read_bytes()
        command = 'source "$1"; render_caddy_configuration "$2" "$3"'
        result = subprocess.run(
            [
                "bash",
                "-c",
                command,
                "bash",
                str(INSTALLER),
                "measurement.example.org",
                str(CADDY_TEMPLATE),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertEqual(CADDY_TEMPLATE.read_bytes(), original)

    def test_main_requires_exactly_one_hostname_before_privileged_work(self) -> None:
        for arguments in ((), ("one.example", "two.example")):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", str(INSTALLER), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Usage: install.sh HOSTNAME", result.stderr)


if __name__ == "__main__":
    unittest.main()
