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
from icprlib import write_json


class CaptureRecoveryTests(unittest.TestCase):
    def test_capture_state_is_durable_before_popen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)

            def interrupted_popen(*_args: object, **_kwargs: object) -> object:
                self.assertEqual(
                    _args[0][0:4],
                    ["sudo", "-n", "/usr/bin/nohup", "/usr/sbin/tcpdump"],
                )
                self.assertIs(_kwargs.get("stdin"), subprocess.DEVNULL)
                self.assertNotIn("start_new_session", _kwargs)
                state = json.loads(
                    (attempt / "capture-state.json").read_text(encoding="utf-8")
                )
                self.assertIsNone(state["pid"])
                self.assertEqual(state["capture_path"], str((attempt / "client.pcap").resolve()))
                self.assertEqual(
                    state["command_argv"][0:4],
                    ["sudo", "-n", "/usr/bin/nohup", "/usr/sbin/tcpdump"],
                )
                raise InterruptedError("simulated interruption before PID persistence")

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops.subprocess, "Popen", side_effect=interrupted_popen),
            ):
                with self.assertRaises(InterruptedError):
                    platform_ops.start_capture(attempt, "en0", "udp port 443", 0x10000)

            self.assertTrue((attempt / "capture-state.json").is_file())
            self.assertFalse((attempt / "capture.pid").exists())

    def test_capture_records_the_durable_tcpdump_child_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            capture_path = attempt / "client.pcap"
            argv = platform_ops.capture_command(
                capture_path, "en0", "udp port 443", 0x10000
            )

            class RunningLauncher:
                pid = 200
                returncode = None

                @staticmethod
                def poll() -> None:
                    return None

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(
                    platform_ops.subprocess, "Popen", return_value=RunningLauncher()
                ),
                mock.patch.object(platform_ops.time, "sleep"),
                mock.patch.object(
                    platform_ops,
                    "matching_capture_pids",
                    return_value={
                        200: " ".join(argv),
                        201: " ".join(argv[3:]),
                    },
                ),
            ):
                pid = platform_ops.start_capture(
                    attempt, "en0", "udp port 443", 0x10000
                )

            self.assertEqual(pid, 201)
            self.assertEqual((attempt / "capture.pid").read_text(), "201\n")
            state = json.loads((attempt / "capture-state.json").read_text())
            self.assertEqual(state["launcher_pid"], 200)
            self.assertEqual(state["pid"], 201)

    def test_exact_command_discovery_ignores_substring_matches(self) -> None:
        expected = {
            "sudo -n /usr/sbin/tcpdump -i en0 -w /tmp/a.pcap udp port 443"
        }
        ps_output = (
            "  101 sudo -n /usr/sbin/tcpdump -i en0 -w /tmp/a.pcap udp port 443\n"
            "  102 wrapper sudo -n /usr/sbin/tcpdump -i en0 -w /tmp/a.pcap udp port 443\n"
            "  103 sudo -n /usr/sbin/tcpdump -i en0 -w /tmp/b.pcap udp port 443\n"
        )
        completed = subprocess.CompletedProcess([], 0, ps_output, "")
        with mock.patch.object(platform_ops.subprocess, "run", return_value=completed):
            self.assertEqual(
                platform_ops.matching_capture_pids(expected),
                {101: next(iter(expected))},
            )

    def test_cleanup_discovers_one_exact_capture_without_pid_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            capture_path = attempt / "client.pcap"
            capture_path.touch()
            argv = platform_ops.capture_command(capture_path, "en0", "udp port 443", 0x10000)
            write_json(
                attempt / "capture-state.json",
                {
                    "pid": None,
                    "capture_path": str(capture_path.resolve()),
                    "interface": "en0",
                    "filter": "udp port 443",
                    "snaplen": 0x10000,
                    "command_argv": argv,
                    "launch_prepared_utc": "2026-08-04T00:00:00Z",
                },
            )
            kill_calls: list[list[str]] = []

            def fake_run(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                kill_calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                mock.patch.object(
                    platform_ops,
                    "matching_capture_pids",
                    return_value={4242: " ".join(argv)},
                ),
                mock.patch.object(platform_ops, "process_running", return_value=False),
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops.subprocess, "run", side_effect=fake_run),
            ):
                platform_ops.stop_capture(attempt)

            self.assertIn(["sudo", "-n", "/bin/kill", "-INT", "4242"], kill_calls)
            state = json.loads((attempt / "capture-state.json").read_text())
            self.assertEqual(state["pid_discovered_during_cleanup"], 4242)
            self.assertIn("stopped_utc", state)

    def test_cleanup_accepts_two_exact_sudo_wrappers_for_recorded_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            capture_path = attempt / "client.pcap"
            capture_path.touch()
            argv = platform_ops.capture_command(
                capture_path, "en0", "udp port 443", 0x10000
            )
            write_json(
                attempt / "capture-state.json",
                {
                    "pid": 43,
                    "capture_path": str(capture_path.resolve()),
                    "interface": "en0",
                    "filter": "udp port 443",
                    "snaplen": 0x10000,
                    "command_argv": argv,
                    "started_utc": "2026-08-04T00:00:00Z",
                },
            )
            (attempt / "capture.pid").write_text("43\n", encoding="utf-8")
            running = {41, 42, 43}

            def fake_running(pid: int) -> bool:
                return pid in running

            def fake_run(
                command: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                if command[0:4] == ["sudo", "-n", "/bin/kill", "-INT"]:
                    running.discard(int(command[-1]))
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                mock.patch.object(
                    platform_ops,
                    "matching_capture_pids",
                    return_value={
                        41: " ".join(argv),
                        42: " ".join(argv),
                        43: " ".join(argv[3:]),
                    },
                ),
                mock.patch.object(
                    platform_ops, "process_running", side_effect=fake_running
                ),
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops.subprocess, "run", side_effect=fake_run),
            ):
                platform_ops.stop_capture(attempt)

            state = json.loads((attempt / "capture-state.json").read_text())
            self.assertEqual(state["exact_capture_pids_signalled"], [41, 42, 43])
            self.assertFalse((attempt / "capture.pid").exists())

    def test_cleanup_refuses_multiple_exact_capture_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            capture_path = attempt / "client.pcap"
            capture_path.touch()
            argv = platform_ops.capture_command(capture_path, "en0", "udp port 443", 0x10000)
            write_json(
                attempt / "capture-state.json",
                {
                    "pid": None,
                    "capture_path": str(capture_path.resolve()),
                    "interface": "en0",
                    "filter": "udp port 443",
                    "snaplen": 0x10000,
                    "command_argv": argv,
                },
            )
            with mock.patch.object(
                platform_ops,
                "matching_capture_pids",
                return_value={41: " ".join(argv), 42: " ".join(argv)},
            ):
                with self.assertRaisesRegex(Exception, "multiple exact"):
                    platform_ops.stop_capture(attempt)

    def test_missing_started_capture_is_marked_as_premature_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            capture_path = attempt / "client.pcap"
            capture_path.write_bytes(b"")
            argv = platform_ops.capture_command(
                capture_path, "en0", "host 203.0.113.10 and udp port 443", 256
            )
            write_json(
                attempt / "capture-state.json",
                {
                    "pid": 4242,
                    "capture_path": str(capture_path.resolve()),
                    "interface": "en0",
                    "filter": "host 203.0.113.10 and udp port 443",
                    "snaplen": 256,
                    "command_argv": argv,
                    "started_utc": "2026-08-04T10:00:00Z",
                },
            )
            (attempt / "capture.pid").write_text("4242\n", encoding="utf-8")
            with (
                mock.patch.object(platform_ops, "matching_capture_pids", return_value={}),
                mock.patch.object(platform_ops, "process_running", return_value=False),
            ):
                platform_ops.stop_capture(attempt)
            state = json.loads((attempt / "capture-state.json").read_text())
            self.assertIn("premature_exit_detected_utc", state)
            self.assertIn("stopped_utc", state)


class HostsRecoveryTests(unittest.TestCase):
    def test_cleanup_infers_completed_install_from_exact_applied_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            baseline = b"127.0.0.1 localhost\n"
            applied = baseline + b"192.0.2.20\tmask.apple-dns.net\t# temporary\n"
            (attempt / "hosts.baseline").write_bytes(baseline)
            write_json(
                attempt / "dns-pin-state.json",
                {
                    "hosts_previous_base64": base64.b64encode(baseline).decode(),
                    "hosts_applied_base64": base64.b64encode(applied).decode(),
                    "hosts_path": "/etc/hosts",
                    "cname_target": "mask.apple-dns.net",
                    "hosts_uid": 0,
                    "hosts_gid": 0,
                    "hosts_mode": "644",
                    "hosts_install_started_utc": "2026-08-04T00:00:00Z",
                },
            )
            current = {"bytes": applied}

            def fake_sudo_bytes(_argv: list[str]) -> bytes:
                return current["bytes"]

            def fake_sudo_run(
                argv: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
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
                platform_ops.restore_dns(attempt)

            state = json.loads((attempt / "dns-pin-state.json").read_text())
            self.assertIn("hosts_install_inferred_utc", state)
            self.assertIn("restored_utc", state)
            self.assertEqual(current["bytes"], baseline)

    def test_cleanup_refuses_ambiguous_partial_hosts_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            baseline = b"127.0.0.1 localhost\n"
            applied = baseline + b"192.0.2.20 mask.apple-dns.net\n"
            (attempt / "hosts.baseline").write_bytes(baseline)
            write_json(
                attempt / "dns-pin-state.json",
                {
                    "hosts_previous_base64": base64.b64encode(baseline).decode(),
                    "hosts_applied_base64": base64.b64encode(applied).decode(),
                    "hosts_path": "/etc/hosts",
                    "cname_target": "mask.apple-dns.net",
                    "hosts_uid": 0,
                    "hosts_gid": 0,
                    "hosts_mode": "644",
                },
            )
            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(
                    platform_ops,
                    "sudo_bytes",
                    return_value=baseline + b"unexpected\n",
                ),
            ):
                with self.assertRaisesRegex(Exception, "ambiguous"):
                    platform_ops.restore_dns(attempt)


class FirewallRecoveryTests(unittest.TestCase):
    anchor = "com.apple/icpr-protocol-diagnostic-v1"
    rule = (
        'block drop out quick on en0 inet proto udp from any to '
        '192.0.2.20 port = 443 label "icpr-protocol-diagnostic-v1-udp-block"'
    )

    def test_recovers_enable_token_and_exact_rule_load_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            output_path = attempt / "pf-enable-output.txt"
            output_path.write_text("pf enabled\nToken : 991\n", encoding="utf-8")
            write_json(
                attempt / "firewall-state.json",
                {
                    "anchor": self.anchor,
                    "condition": "udp_blocked",
                    "pf_was_enabled": False,
                    "pf_enable_required": True,
                    "pf_enable_token": "",
                    "pf_enable_started_utc": "2026-08-04T00:00:00Z",
                    "pf_enable_output_path": str(output_path.resolve()),
                    "exact_rule": self.rule,
                    "rule_loaded": False,
                    "rule_load_started_utc": "2026-08-04T00:00:01Z",
                },
            )
            current = {"rules": self.rule}
            commands: list[list[str]] = []

            def fake_sudo_run(
                argv: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                commands.append(argv)
                if argv[-1:] == ["-sr"]:
                    return subprocess.CompletedProcess(argv, 0, current["rules"], "")
                if argv[-2:] == ["-F", "rules"]:
                    current["rules"] = ""
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops, "sudo_run", side_effect=fake_sudo_run),
            ):
                platform_ops.restore_firewall(attempt)

            self.assertIn(["/sbin/pfctl", "-a", self.anchor, "-F", "rules"], commands)
            self.assertIn(["/sbin/pfctl", "-X", "991"], commands)
            state = json.loads((attempt / "firewall-state.json").read_text())
            self.assertIn("rule_load_inferred_utc", state)
            self.assertIn("pf_enable_reference_released_utc", state)
            self.assertIn("restored_utc", state)

    def test_refuses_enable_window_without_captured_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            write_json(
                attempt / "firewall-state.json",
                {
                    "anchor": self.anchor,
                    "pf_was_enabled": False,
                    "pf_enable_required": True,
                    "pf_enable_started_utc": "2026-08-04T00:00:00Z",
                    "pf_enable_token": "",
                    "exact_rule": self.rule,
                    "rule_loaded": False,
                },
            )
            with mock.patch.object(platform_ops, "sudo_ready"):
                with self.assertRaisesRegex(Exception, "no enable token"):
                    platform_ops.restore_firewall(attempt)

    def test_refuses_nonexact_rule_without_clearing_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            write_json(
                attempt / "firewall-state.json",
                {
                    "anchor": self.anchor,
                    "pf_was_enabled": True,
                    "pf_enable_required": False,
                    "pf_enable_token": "",
                    "exact_rule": self.rule,
                    "rule_loaded": False,
                    "rule_load_started_utc": "2026-08-04T00:00:00Z",
                },
            )
            commands: list[list[str]] = []

            def fake_sudo_run(
                argv: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                commands.append(argv)
                return subprocess.CompletedProcess(argv, 0, "block drop out all", "")

            with (
                mock.patch.object(platform_ops, "sudo_ready"),
                mock.patch.object(platform_ops, "sudo_run", side_effect=fake_sudo_run),
            ):
                with self.assertRaisesRegex(Exception, "ambiguous"):
                    platform_ops.restore_firewall(attempt)

            self.assertNotIn(["/sbin/pfctl", "-a", self.anchor, "-F", "rules"], commands)


if __name__ == "__main__":
    unittest.main()
