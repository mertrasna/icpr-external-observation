#!/usr/bin/env python3
"""Semi-automatic, operator-controlled Step 9 experiment controller."""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import fcntl
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from icprlib import (
    CONFIG_PATH,
    EXPERIMENT_ROOT,
    PINS_PATH,
    IcprError,
    active_interface,
    all_ipv4_answers,
    append_jsonl,
    configuration_gaps,
    dependency_status,
    dig_snapshot,
    finalize_attempt,
    load_json_yaml,
    load_pins,
    network_type,
    parse_utc,
    sha256_file,
    software_snapshot,
    utc_now,
    verify_attempt,
    verify_sidecar,
    write_json,
    write_sidecar,
)
from pipeline import PairingPipeline, _load_asn_rows, _load_operator_map, _read_apple_feed


LIVE_APPROVAL = "OPEN_ONE_SAFARI_URL"
DNS_APPROVAL = "APPLY_DNS_PIN"
FIREWALL_APPROVAL = "APPLY_TARGETED_UDP_BLOCK"
DISRUPTIVE_APPROVAL = "ALTER_PRIVATE_RELAY_PROCESS_STATE"
REAL_IP_APPROVAL = "SEND_REAL_IP_CONTROL"

ALLOWED_PIN_HOSTNAMES = {"mask.icloud.com", "mask-h2.icloud.com"}
ALLOWED_PIN_CNAME_TARGET = "mask.apple-dns.net"
ALLOWED_HOSTS_FILE = "/etc/hosts"
# Retained only so interrupted attempts created by the superseded resolver-stub
# mechanism can still be recovered safely.
ALLOWED_RESOLVER_FILES = {
    "/etc/resolver/mask.icloud.com",
    "/etc/resolver/mask-h2.icloud.com",
}
ALLOWED_PF_ANCHOR = "com.apple/icpr-step9"
STATUS_SCHEMA_VERSION = "v1"

GATE_REQUIRED_CHECKS: dict[str, set[str]] = {
    "synthetic_tests": {"synthetic_suite_passed"},
    "privileged_smoke": {
        "capture_start_stop",
        "dns_pin_restore",
        "targeted_pf_restore",
    },
    "smoke_reconstruction": {
        "direct_off_control",
        "relay_on_unpinned",
        "akamai_pinned",
        "apple_as714_pinned",
        "both_location_settings",
        "hash_verified_reconstruction",
    },
    "rehearsal_completion": {
        "six_hour_limit_observed",
        "all_attempts_accounted",
        "cleanup_verified",
        "hashes_verified",
    },
    "final_campaign_freeze": {
        "configuration_frozen",
        "script_hashes_frozen",
        "rehearsal_approved",
    },
}


def log(message: str) -> None:
    print(f"[icpr-step9] {message}")


def fail(message: str) -> None:
    raise IcprError(message)


def generate_run_id() -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"icpr-{timestamp}-{secrets.token_hex(8)}"


def controller_sha256() -> str:
    return sha256_file(Path(__file__).resolve())


def privileged_configuration_blockers(config: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    pinning = config.get("pinning") or {}
    hostnames = pinning.get("hostnames")
    if (
        not isinstance(hostnames, list)
        or not all(isinstance(value, str) for value in hostnames)
        or set(hostnames) != ALLOWED_PIN_HOSTNAMES
        or len(hostnames) != len(ALLOWED_PIN_HOSTNAMES)
    ):
        blockers.append("pinning.hostnames must contain exactly mask.icloud.com and mask-h2.icloud.com")
    if pinning.get("cname_target") != ALLOWED_PIN_CNAME_TARGET:
        blockers.append(f"pinning.cname_target must be {ALLOWED_PIN_CNAME_TARGET}")
    if pinning.get("hosts_file") != ALLOWED_HOSTS_FILE:
        blockers.append(f"pinning.hosts_file must be {ALLOWED_HOSTS_FILE}")
    if pinning.get("restart_networkserviceproxy") is not True:
        blockers.append("pinning.restart_networkserviceproxy must be true")
    fallback = config.get("targeted_fallback") or {}
    if fallback.get("pf_anchor") != ALLOWED_PF_ANCHOR:
        blockers.append(f"targeted_fallback.pf_anchor must be {ALLOWED_PF_ANCHOR}")
    for key in (
        "load_rule_before_dns_pin_restart",
        "reset_only_states_to_confirmed_ingress",
        "require_positive_pf_block_counter",
        "require_client_tcp_443_to_pinned_ingress",
        "mask_h2_dns_query_is_supporting_not_required",
        "measurement_server_udp_443_must_remain_available",
        "require_private_relay_egress_at_destination",
        "reject_real_ip_bypass",
    ):
        if fallback.get(key) is not True:
            blockers.append(f"targeted_fallback.{key} must be true")
    return blockers


def require_safe_privileged_configuration(config: dict[str, Any]) -> None:
    blockers = privileged_configuration_blockers(config)
    if blockers:
        fail("unsafe privileged configuration: " + "; ".join(blockers))


def process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # kill(0) also succeeds for a terminated child that has not yet been
    # reaped.  Treat that zombie as stopped so recovery does not remain
    # blocked after the DNS stub or capture process has actually exited.
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "stat=", "-p", str(pid)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return True
    status = result.stdout.strip()
    if result.returncode == 0 and status:
        return not status.startswith("Z")
    # The process may have exited between kill(0) and ps.  Confirm once more;
    # if inspection itself is unavailable, conservatively report it running.
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def process_command(pid: int) -> str:
    return subprocess.run(
        ["/bin/ps", "-o", "command=", "-p", str(pid)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()


def hosts_target_entries(content: bytes, target: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    text = content.decode("utf-8", errors="strict")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        fields = raw_line.split("#", 1)[0].split()
        if len(fields) >= 2 and target in fields[1:]:
            entries.append(
                {"line_number": line_number, "address": fields[0], "line": raw_line}
            )
    return entries


def render_hosts_override(content: bytes, target: str, pin_ip: str) -> bytes:
    if hosts_target_entries(content, target):
        fail(f"baseline /etc/hosts already contains an unmanaged entry for {target}")
    separator = b"" if not content or content.endswith(b"\n") else b"\n"
    return content + separator + f"{pin_ip}\t{target}\t# icpr-step9 temporary\n".encode()


def hosts_override_status(config: dict[str, Any]) -> dict[str, Any]:
    pinning = config.get("pinning") or {}
    path = Path(str(pinning.get("hosts_file", ALLOWED_HOSTS_FILE)))
    target = str(pinning.get("cname_target", ALLOWED_PIN_CNAME_TARGET))
    try:
        entries = hosts_target_entries(path.read_bytes(), target)
        return {
            "path": str(path),
            "target": target,
            "baseline_clean": not entries,
            "entries": entries,
        }
    except (OSError, UnicodeDecodeError) as exc:
        return {
            "path": str(path),
            "target": target,
            "baseline_clean": False,
            "error": str(exc),
        }


def ipv6_default_route_status() -> dict[str, Any]:
    result = subprocess.run(
        ["/sbin/route", "-n", "get", "-inet6", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    combined = (result.stdout + result.stderr).strip()
    confirmed_absent = "not in table" in combined.lower()
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "present": result.returncode == 0 and not confirmed_absent,
        "confirmed_absent": confirmed_absent,
    }


def dscacheutil_addresses(output: str) -> tuple[list[str], list[str]]:
    ipv4 = re.findall(r"^ip_address:\s*(\S+)\s*$", output, flags=re.MULTILINE)
    ipv6 = re.findall(r"^ipv6_address:\s*(\S+)\s*$", output, flags=re.MULTILINE)
    return ipv4, ipv6


def macos_effective_resolver_snapshot(
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Record exact IPv4 candidates returned by the effective macOS resolver."""

    pinning = config["pinning"]
    names = list(
        dict.fromkeys([*pinning["hostnames"], pinning["cname_target"]])
    )
    snapshot: dict[str, Any] = {"recorded_utc": utc_now(), "lookups": {}}
    addresses: set[str] = set()
    for name in names:
        result = subprocess.run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        ipv4, ipv6 = dscacheutil_addresses(result.stdout)
        normalized_ipv4: list[str] = []
        for address in ipv4:
            try:
                normalized = str(ipaddress.IPv4Address(address))
            except ipaddress.AddressValueError:
                continue
            normalized_ipv4.append(normalized)
            addresses.add(normalized)
        snapshot["lookups"][name] = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "ipv4": sorted(set(normalized_ipv4), key=ipaddress.IPv4Address),
            "ipv6": sorted(set(ipv6)),
        }
    return snapshot, sorted(addresses, key=ipaddress.IPv4Address)


def resolver_plan(config: dict[str, Any], pin_ip: str) -> dict[str, Any]:
    require_safe_privileged_configuration(config)
    pinning = config["pinning"]
    return {
        "mechanism": "temporary /etc/hosts override of the shared Private Relay CNAME target",
        "pin_ipv4": pin_ip,
        "hostnames": pinning["hostnames"],
        "cname_target": pinning["cname_target"],
        "file_modified_temporarily": pinning["hosts_file"],
        "activation": "flush macOS DNS caches and restart networkserviceproxy",
        "ipv6_policy": "public AAAA answers are recorded but accepted only when the IPv6 default route is confirmed absent; primary analysis is IPv4",
        "cleanup": "restore /etc/hosts byte-for-byte, flush caches, and restart networkserviceproxy",
        "truth_source": "the selected ingress must still appear in the Mac pcap",
        "approval_tokens": [DNS_APPROVAL, DISRUPTIVE_APPROVAL],
    }


def firewall_plan(config: dict[str, Any], pin_ip: str, interface: str) -> dict[str, Any]:
    require_safe_privileged_configuration(config)
    anchor = config["targeted_fallback"]["pf_anchor"]
    rule = (
        f"block drop out quick on {interface} inet proto udp "
        f"from any to {pin_ip} port = 443 label \"icpr-step9-udp-block\""
    )
    return {
        "mechanism": "temporary rule in the existing macOS com.apple/* PF anchor namespace",
        "anchor": anchor,
        "exact_rule": rule,
        "scope": "only UDP/443 to the confirmed pinned ingress IPv4",
        "targeted_state_reset": (
            "after loading the rule, remove only existing PF states whose destination "
            "is the confirmed pinned ingress IPv4"
        ),
        "proof": "record the targeted rule packet counters before cleanup",
        "global_udp_443_block": False,
        "cleanup": "flush only this anchor and release only the PF enable reference acquired by the helper",
        "fallback_proof": "Mac pcap must show TCP/443 to mask-h2 ingress; server must still see a feed-valid relay egress",
        "approval_token": FIREWALL_APPROVAL,
    }


def pf_rule_statistics(snapshot: str) -> dict[str, int]:
    """Normalize the counters printed by macOS pfctl -vvs rules."""
    statistics: dict[str, int] = {}
    for key in ("Evaluations", "Packets", "Bytes", "States"):
        match = re.search(rf"\b{key}:\s*([0-9]+)\b", snapshot)
        if match:
            statistics[key.lower()] = int(match.group(1))
    return statistics


def sudo_ready(*, noninteractive: bool = False) -> None:
    argv = ["sudo", "-n", "-v"] if noninteractive else ["sudo", "-v"]
    result = subprocess.run(argv, check=False)
    if result.returncode != 0:
        fail("sudo authentication was not approved")


def _sudo(argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["sudo", "-n", *argv],
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"privileged command failed: {' '.join(argv)}: {result.stderr.strip()}")
    return result


def _sudo_bytes(argv: list[str]) -> bytes:
    result = subprocess.run(
        ["sudo", "-n", *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(
            f"privileged command failed: {' '.join(argv)}: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return result.stdout


def clear_networkserviceproxy_state() -> dict[str, Any]:
    result = subprocess.run(
        ["sudo", "-n", "/usr/bin/killall", "networkserviceproxy"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    combined = (result.stdout + result.stderr).lower()
    already_absent = "no matching process" in combined
    if result.returncode != 0 and not already_absent:
        fail(
            "privileged command failed: /usr/bin/killall networkserviceproxy: "
            + result.stderr.strip()
        )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": "already_absent" if already_absent else "terminated",
    }


def apply_dns_pin(attempt_dir: Path, config: dict[str, Any], pin_ip: str) -> dict[str, Any]:
    require_safe_privileged_configuration(config)
    sudo_ready()
    pinning = config["pinning"]
    hosts_path = str(pinning["hosts_file"])
    target = str(pinning["cname_target"])
    if subprocess.run(["sudo", "-n", "test", "-L", hosts_path], check=False).returncode == 0:
        fail(f"refusing to replace hosts symlink: {hosts_path}")
    if subprocess.run(["sudo", "-n", "test", "-f", hosts_path], check=False).returncode != 0:
        fail(f"refusing to replace missing or non-regular hosts file: {hosts_path}")
    previous = _sudo_bytes(["/bin/cat", hosts_path])
    if hosts_target_entries(previous, target):
        fail(f"baseline {hosts_path} already contains an unmanaged entry for {target}")
    stat_fields = _sudo(["/usr/bin/stat", "-f", "%u %g %Lp", hosts_path]).stdout.split()
    applied = render_hosts_override(previous, target, pin_ip)
    state: dict[str, Any] = {
        "mechanism": "hosts_cname_override_v1",
        "applied_utc": utc_now(),
        "pin_ip": pin_ip,
        "hosts_path": hosts_path,
        "cname_target": target,
        "hosts_previous_base64": base64.b64encode(previous).decode("ascii"),
        "hosts_applied_base64": base64.b64encode(applied).decode("ascii"),
        "hosts_uid": int(stat_fields[0]),
        "hosts_gid": int(stat_fields[1]),
        "hosts_mode": stat_fields[2],
    }
    state_path = attempt_dir / "dns-pin-state.json"
    write_json(state_path, state)
    applied_path = attempt_dir / "hosts.applied"
    applied_path.write_bytes(applied)
    _sudo(
        [
            "/usr/bin/install",
            "-o",
            str(state["hosts_uid"]),
            "-g",
            str(state["hosts_gid"]),
            "-m",
            str(state["hosts_mode"]),
            str(applied_path),
            hosts_path,
        ]
    )
    state["hosts_installed_utc"] = utc_now()
    write_json(state_path, state)
    _sudo(["/usr/bin/dscacheutil", "-flushcache"])
    _sudo(["/usr/bin/killall", "-HUP", "mDNSResponder"])
    state["networkserviceproxy_activation"] = clear_networkserviceproxy_state()
    state["networkserviceproxy_state_cleared_utc"] = utc_now()
    effective = subprocess.run(
        ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", target],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    state["macos_effective_hosts_check"] = {
        "returncode": effective.returncode,
        "stdout": effective.stdout,
        "stderr": effective.stderr,
    }
    ipv6_route = ipv6_default_route_status()
    state["ipv6_default_route_check"] = ipv6_route
    write_json(state_path, state)
    ipv4_addresses, ipv6_addresses = dscacheutil_addresses(effective.stdout)
    if effective.returncode != 0 or set(ipv4_addresses) != {pin_ip}:
        fail(f"macOS effective IPv4 lookup for {target} did not return only the approved pin")
    if ipv6_addresses and not ipv6_route["confirmed_absent"]:
        fail(
            "the pin target has public IPv6 answers and IPv6 bypass cannot be "
            "excluded because no-route status was not confirmed"
        )
    return state


def apply_firewall(attempt_dir: Path, config: dict[str, Any], pin_ip: str, interface: str) -> dict[str, Any]:
    require_safe_privileged_configuration(config)
    sudo_ready()
    plan = firewall_plan(config, pin_ip, interface)
    server_addresses = {
        item[4][0]
        for item in socket.getaddrinfo(config["server"]["hostname"], 443, type=socket.SOCK_DGRAM)
    }
    if pin_ip in server_addresses:
        fail("refusing a fallback rule that would block UDP/443 to the measurement server")
    anchor = plan["anchor"]
    previous = _sudo(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip()
    if previous:
        fail(f"PF anchor {anchor} is not empty; refusing to replace existing rules")
    status = _sudo(["/sbin/pfctl", "-s", "info"]).stdout
    was_enabled = "Status: Enabled" in status
    token = ""
    if not was_enabled:
        enabled = _sudo(["/sbin/pfctl", "-E"])
        combined = enabled.stdout + enabled.stderr
        match = re.search(r"Token\s*:\s*([0-9]+)", combined, flags=re.IGNORECASE)
        if match:
            token = match.group(1)
        else:
            write_json(
                attempt_dir / "firewall-state.json",
                {
                    **plan,
                    "activation_error_utc": utc_now(),
                    "pf_was_enabled": False,
                    "unparsed_enable_output": combined,
                },
            )
            fail("PF was initially disabled and its enable token could not be recorded")
    state = {
        **plan,
        "activated_utc": utc_now(),
        "pf_was_enabled": was_enabled,
        "pf_enable_token": token,
        "previous_anchor_rules": previous,
        "measurement_server_addresses": sorted(server_addresses),
    }
    state_path = attempt_dir / "firewall-state.json"
    write_json(state_path, state)
    state["rule_load_started_utc"] = utc_now()
    write_json(state_path, state)
    _sudo(["/sbin/pfctl", "-a", anchor, "-f", "-"], input_text=plan["exact_rule"] + "\n")
    state["rule_loaded"] = True
    state["loaded_rules_snapshot"] = _sudo(
        ["/sbin/pfctl", "-a", anchor, "-sr"]
    ).stdout.strip()
    write_json(state_path, state)
    loaded_lines = [
        line.strip()
        for line in state["loaded_rules_snapshot"].splitlines()
        if line.strip()
    ]
    required_fragments = (
        "block drop out quick",
        f"on {interface}",
        "inet proto udp",
        f"to {pin_ip}",
        "port = 443",
        'label "icpr-step9-udp-block"',
    )
    if len(loaded_lines) != 1 or not all(
        fragment in loaded_lines[0] for fragment in required_fragments
    ):
        fail("loaded PF anchor does not contain exactly the approved targeted rule")
    state_reset = _sudo(
        ["/sbin/pfctl", "-k", "0.0.0.0/0", "-k", pin_ip]
    )
    state["targeted_state_reset_utc"] = utc_now()
    state["targeted_state_reset_output"] = (
        state_reset.stdout + state_reset.stderr
    ).strip()
    write_json(state_path, state)
    return state


def snapshot_firewall_statistics(attempt_dir: Path) -> None:
    """Record PF counters before any cleanup; failure must not prevent cleanup."""
    state_path = attempt_dir / "firewall-state.json"
    if not state_path.is_file():
        return
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("restored_utc"):
            return
        snapshot = _sudo(
            ["/sbin/pfctl", "-a", str(state.get("anchor", "")), "-vvs", "rules"]
        ).stdout.strip()
        state["rule_statistics_before_cleanup_utc"] = utc_now()
        state["rule_statistics_before_cleanup_snapshot"] = snapshot
        state["rule_statistics_before_cleanup"] = pf_rule_statistics(snapshot)
        write_json(state_path, state)
    except (IcprError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(state, dict):
                state["rule_statistics_before_cleanup_error"] = str(exc)
                write_json(state_path, state)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass


def cleanup_attempt(
    attempt_dir: Path, config: dict[str, Any], *, noninteractive: bool = False
) -> list[str]:
    actions: list[str] = []
    errors: list[str] = []

    snapshot_firewall_statistics(attempt_dir)

    def load_state(path: Path, label: str) -> dict[str, Any]:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            fail(f"{label} state is not an object")
        return state

    def positive_pid(value: Any, label: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 1:
            fail(f"{label} must be an integer greater than one")
        return value

    def optional_utc(state: dict[str, Any], field: str, label: str) -> bool:
        value = state.get(field)
        if value in (None, ""):
            return False
        parse_utc(value)
        return True

    def cleanup_capture() -> str | None:
        capture_pid_path = attempt_dir / "capture.pid"
        if not capture_pid_path.is_file():
            return None
        pid_text = capture_pid_path.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9]+", pid_text):
            fail("capture.pid is not a positive decimal PID")
        pid = positive_pid(int(pid_text), "capture.pid")
        capture_state_path = attempt_dir / "capture-state.json"
        if not capture_state_path.is_file():
            fail("capture PID exists without capture-state.json")
        capture_state = load_state(capture_state_path, "capture")
        state_pid = positive_pid(capture_state.get("pid"), "capture-state.json pid")
        if state_pid != pid:
            fail("capture PID does not match capture-state.json")
        signal_scope = capture_state.get("signal_scope", "process_group")
        if signal_scope not in {"pid", "process_group"}:
            fail("capture-state.json has an invalid signal scope")
        if signal_scope == "process_group" and capture_state.get("process_group") != pid:
            fail("capture-state.json process group does not match its PID")
        if signal_scope == "pid" and capture_state.get("process_group") is not None:
            fail("PID-scoped capture state must not name a process group")
        capture_path = capture_state.get("capture_path")
        if not isinstance(capture_path, str) or not capture_path:
            fail("capture-state.json has no valid capture path")
        expected_capture = (attempt_dir / "client.pcap").resolve()
        if Path(capture_path).expanduser().resolve() != expected_capture:
            fail("capture-state.json path is outside the expected attempt capture")
        optional_utc(capture_state, "stopped_utc", "capture")
        if process_running(pid):
            command = process_command(pid)
            if "tcpdump" not in command or capture_path not in command:
                fail(f"capture PID {pid} was reused or does not match the recorded command")
            sudo_ready(noninteractive=noninteractive)
            if signal_scope == "process_group":
                result = subprocess.run(
                    ["sudo", "-n", "/bin/kill", "-INT", "--", f"-{pid}"],
                    check=False,
                )
            else:
                result = subprocess.run(
                    ["sudo", "-n", "/bin/kill", "-INT", str(pid)], check=False
                )
            if result.returncode != 0 and signal_scope == "process_group":
                _sudo(["/bin/kill", "-INT", str(pid)])
            elif result.returncode != 0:
                fail(f"capture process {pid} could not be signaled")
            deadline = time.monotonic() + 10
            while process_running(pid) and time.monotonic() < deadline:
                time.sleep(0.2)
            if process_running(pid):
                fail(f"capture process {pid} did not stop; cleanup remains required")
        residual = subprocess.run(
            ["/usr/bin/pgrep", "-f", capture_path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        ).stdout.strip()
        if residual:
            fail(f"capture child process still references {capture_path}: {residual}")
        capture_state.setdefault("stopped_utc", utc_now())
        write_json(capture_state_path, capture_state)
        capture_pid_path.unlink(missing_ok=True)
        return "client capture stopped"

    def cleanup_dns() -> str | None:
        dns_state_path = attempt_dir / "dns-pin-state.json"
        if not dns_state_path.is_file():
            return None
        state = load_state(dns_state_path, "DNS")
        already_restored = optional_utc(state, "restored_utc", "DNS")
        if state.get("mechanism") == "hosts_cname_override_v1":
            if state.get("hosts_path") != ALLOWED_HOSTS_FILE:
                fail("DNS hosts state names an unapproved hosts file")
            if state.get("cname_target") != ALLOWED_PIN_CNAME_TARGET:
                fail("DNS hosts state names an unapproved CNAME target")
            for field in (
                "hosts_installed_utc",
                "networkserviceproxy_restarted_utc",
                "networkserviceproxy_state_cleared_utc",
                "hosts_restored_utc",
                "resolver_cache_flushed_utc",
                "networkserviceproxy_cleanup_restart_utc",
            ):
                optional_utc(state, field, "DNS hosts override")
            try:
                previous = base64.b64decode(
                    state["hosts_previous_base64"], validate=True
                )
                applied = base64.b64decode(
                    state["hosts_applied_base64"], validate=True
                )
                uid = int(state["hosts_uid"])
                gid = int(state["hosts_gid"])
                mode = str(state["hosts_mode"])
            except (KeyError, TypeError, ValueError) as exc:
                fail(f"DNS hosts state is incomplete or malformed: {exc}")
            if uid < 0 or gid < 0 or not re.fullmatch(r"0?[0-7]{3,4}", mode):
                fail("DNS hosts ownership or mode is invalid")
            if hosts_target_entries(previous, ALLOWED_PIN_CNAME_TARGET):
                fail("saved baseline hosts file already contains the pin target")
            if not hosts_target_entries(applied, ALLOWED_PIN_CNAME_TARGET):
                fail("saved applied hosts file lacks the pin target")
            if already_restored:
                sudo_ready(noninteractive=noninteractive)
                if _sudo_bytes(["/bin/cat", ALLOWED_HOSTS_FILE]) != previous:
                    fail("restored hosts file no longer matches the saved baseline")
                return None
            sudo_ready(noninteractive=noninteractive)
            current = _sudo_bytes(["/bin/cat", ALLOWED_HOSTS_FILE])
            installed = bool(state.get("hosts_installed_utc"))
            if installed and current != applied:
                fail("conflict at /etc/hosts; refusing to overwrite a concurrent change")
            if not installed and current != previous:
                fail("partial hosts activation differs from both saved states")
            if installed:
                restored_file = attempt_dir / "hosts.previous"
                restored_file.write_bytes(previous)
                _sudo(
                    [
                        "/usr/bin/install",
                        "-o",
                        str(uid),
                        "-g",
                        str(gid),
                        "-m",
                        mode,
                        str(restored_file),
                        ALLOWED_HOSTS_FILE,
                    ]
                )
                state["hosts_restored_utc"] = utc_now()
                _sudo(["/usr/bin/dscacheutil", "-flushcache"])
                _sudo(["/usr/bin/killall", "-HUP", "mDNSResponder"])
                state["resolver_cache_flushed_utc"] = utc_now()
                state["networkserviceproxy_cleanup"] = (
                    clear_networkserviceproxy_state()
                )
                state["networkserviceproxy_cleanup_restart_utc"] = utc_now()
            if _sudo_bytes(["/bin/cat", ALLOWED_HOSTS_FILE]) != previous:
                fail("hosts file does not match the saved baseline after cleanup")
            state["restored_utc"] = utc_now()
            write_json(dns_state_path, state)
            return "previous /etc/hosts state restored"

        previous_values = state.get("resolver_previous")
        applied_values = state.get("resolver_applied")
        if not isinstance(previous_values, dict) or not isinstance(applied_values, dict):
            fail("DNS state lacks resolver snapshots")
        if not set(previous_values).issubset(ALLOWED_RESOLVER_FILES) or not set(
            applied_values
        ).issubset(ALLOWED_RESOLVER_FILES):
            fail("DNS state contains a resolver path outside the approved pair")
        if not set(applied_values).issubset(previous_values):
            fail("DNS state has an applied resolver without a previous-state snapshot")
        for path_text, previous in previous_values.items():
            if not isinstance(path_text, str) or not isinstance(previous, dict):
                fail("DNS previous resolver snapshots are malformed")
            existed = previous.get("existed")
            if not isinstance(existed, bool):
                fail(f"DNS previous resolver snapshot has invalid existed flag: {path_text}")
            if existed:
                encoded = previous.get("base64")
                uid = previous.get("uid")
                gid = previous.get("gid")
                mode = previous.get("mode")
                if not isinstance(encoded, str):
                    fail(f"DNS previous resolver snapshot lacks base64 data: {path_text}")
                try:
                    base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError) as exc:
                    fail(f"DNS previous resolver snapshot has invalid base64: {path_text}: {exc}")
                if (
                    isinstance(uid, bool)
                    or not isinstance(uid, int)
                    or uid < 0
                    or isinstance(gid, bool)
                    or not isinstance(gid, int)
                    or gid < 0
                    or not isinstance(mode, str)
                    or not re.fullmatch(r"0?[0-7]{3,4}", mode)
                ):
                    fail(f"DNS previous resolver ownership or mode is invalid: {path_text}")
        if any(not isinstance(value, str) or not value for value in applied_values.values()):
            fail("DNS applied resolver snapshots must be nonempty strings")
        restored_paths = state.get("resolver_restored", {})
        if not isinstance(restored_paths, dict):
            fail("DNS resolver_restored state is not an object")
        if not set(restored_paths).issubset(applied_values):
            fail("DNS resolver_restored contains a path that was never applied")
        for restored_utc in restored_paths.values():
            parse_utc(restored_utc)
        state["resolver_restored"] = restored_paths
        cache_flushed = optional_utc(state, "resolver_cache_flushed_utc", "DNS resolver cache")
        pid_value = state.get("dns_stub_pid")
        pid = positive_pid(pid_value, "DNS stub PID") if pid_value is not None else 0
        if pid:
            query_log = state.get("dns_stub_query_log")
            expected_log = (attempt_dir / "dns-queries.jsonl").resolve()
            if (
                not isinstance(query_log, str)
                or Path(query_log).expanduser().resolve() != expected_log
            ):
                fail("DNS stub query-log path is outside the expected attempt artifact")
        stub_stopped = optional_utc(state, "dns_stub_stopped_utc", "DNS stub")
        if already_restored:
            if set(restored_paths) != set(applied_values):
                fail("DNS restored state does not account for every applied resolver path")
            if applied_values and not cache_flushed:
                fail("DNS restored state lacks a resolver-cache flush timestamp")
            if pid and not stub_stopped:
                fail("DNS restored state lacks a DNS-stub stop timestamp")
            return None
        path_errors: list[str] = []
        for path_text, previous in previous_values.items():
            if path_text not in applied_values or path_text in restored_paths:
                continue
            try:
                sudo_ready(noninteractive=noninteractive)
                applied = str(applied_values[path_text]).encode("utf-8")
                current_exists = subprocess.run(
                    ["sudo", "-n", "test", "-e", path_text], check=False
                ).returncode == 0
                current_is_symlink = subprocess.run(
                    ["sudo", "-n", "test", "-L", path_text], check=False
                ).returncode == 0
                if (
                    not current_exists
                    or current_is_symlink
                    or _sudo_bytes(["/bin/cat", path_text]) != applied
                ):
                    raise IcprError(
                        f"conflict at {path_text}; refusing to overwrite a concurrent change"
                    )
                if previous.get("existed"):
                    restored = attempt_dir / (Path(path_text).name + ".previous")
                    restored.write_bytes(base64.b64decode(previous["base64"], validate=True))
                    _sudo(
                        [
                            "/usr/bin/install",
                            "-o",
                            str(previous["uid"]),
                            "-g",
                            str(previous["gid"]),
                            "-m",
                            str(previous["mode"]),
                            str(restored),
                            path_text,
                        ]
                    )
                else:
                    _sudo(["/bin/rm", "-f", path_text])
                restored_paths[path_text] = utc_now()
                write_json(dns_state_path, state)
            except (IcprError, OSError, ValueError, KeyError) as exc:
                path_errors.append(str(exc))
        if applied_values and not cache_flushed:
            sudo_ready(noninteractive=noninteractive)
            _sudo(["/usr/bin/dscacheutil", "-flushcache"])
            _sudo(["/usr/bin/killall", "-HUP", "mDNSResponder"])
            state["resolver_cache_flushed_utc"] = utc_now()
            write_json(dns_state_path, state)
        if pid and not state.get("dns_stub_stopped_utc") and process_running(pid):
            command = process_command(pid)
            if (
                "dns_stub.py" not in command
                or state.get("dns_stub_query_log", "") not in command
            ):
                path_errors.append(
                    f"DNS stub PID {pid} was reused; refusing to signal it"
                )
            else:
                os.killpg(pid, signal.SIGTERM)
                deadline = time.monotonic() + 5
                while process_running(pid) and time.monotonic() < deadline:
                    time.sleep(0.1)
                if process_running(pid):
                    path_errors.append(f"DNS stub process group {pid} did not stop")
                else:
                    state["dns_stub_stopped_utc"] = utc_now()
        elif pid and not process_running(pid):
            state.setdefault("dns_stub_stopped_utc", utc_now())
        if path_errors:
            write_json(dns_state_path, state)
            fail("; ".join(path_errors))
        if set(restored_paths) != set(applied_values):
            fail("not every applied resolver path has a recorded restoration")
        state["restored_utc"] = utc_now()
        write_json(dns_state_path, state)
        return "previous DNS resolver state restored"

    def cleanup_firewall() -> str | None:
        firewall_state_path = attempt_dir / "firewall-state.json"
        if not firewall_state_path.is_file():
            return None
        state = load_state(firewall_state_path, "PF")
        already_restored = optional_utc(state, "restored_utc", "PF")
        if state.get("anchor") != ALLOWED_PF_ANCHOR:
            fail("PF state names an anchor outside the dedicated Step 9 anchor")
        for field in (
            "rule_load_started_utc",
            "rules_cleared_utc",
            "pf_enable_reference_released_utc",
            "activation_error_utc",
        ):
            optional_utc(state, field, "PF")
        if "rule_loaded" in state and not isinstance(state["rule_loaded"], bool):
            fail("PF rule_loaded must be Boolean")
        if "pf_was_enabled" not in state or not isinstance(state["pf_was_enabled"], bool):
            fail("PF pf_was_enabled must be Boolean")
        loaded_snapshot = state.get("loaded_rules_snapshot", "")
        if not isinstance(loaded_snapshot, str):
            fail("PF loaded_rules_snapshot must be text")
        if state.get("rule_loaded") and not loaded_snapshot.strip():
            fail("PF rule_loaded is true without a recorded loaded-rules snapshot")
        token = state.get("pf_enable_token")
        if token not in (None, "") and not re.fullmatch(r"[1-9][0-9]*", str(token)):
            fail("PF enable token is malformed")
        if state["pf_was_enabled"] is True and token not in (None, ""):
            fail("PF state records an enable token even though PF was already enabled")
        if state["pf_was_enabled"] is False and not token:
            fail("PF was enabled without a recorded reference token; manual recovery is required")
        if already_restored:
            if not state.get("rules_cleared_utc"):
                fail("PF restored state lacks a rules-cleared timestamp")
            if token and not state.get("pf_enable_reference_released_utc"):
                fail("PF restored state lacks an enable-reference release timestamp")
            return None
        sudo_ready(noninteractive=noninteractive)
        if not state.get("rules_cleared_utc"):
            current_rules = _sudo(
                ["/sbin/pfctl", "-a", state["anchor"], "-sr"]
            ).stdout.strip()
            if state.get("rule_loaded") and current_rules != loaded_snapshot:
                fail(
                    f"PF cleanup conflict in {state['anchor']}; current rule differs from this attempt"
                )
            if not state.get("rule_loaded") and current_rules:
                fail(
                    f"PF cleanup conflict in {state['anchor']}; rules exist without verified load state"
                )
            if current_rules:
                _sudo(["/sbin/pfctl", "-a", state["anchor"], "-F", "rules"])
            if _sudo(["/sbin/pfctl", "-a", state["anchor"], "-sr"]).stdout.strip():
                fail(f"PF anchor {state['anchor']} is not empty after cleanup")
            state["rules_cleared_utc"] = utc_now()
            write_json(firewall_state_path, state)
        if token and not state.get("pf_enable_reference_released_utc"):
            _sudo(["/sbin/pfctl", "-X", str(token)])
            state["pf_enable_reference_released_utc"] = utc_now()
            write_json(firewall_state_path, state)
        state["restored_utc"] = utc_now()
        write_json(firewall_state_path, state)
        return "targeted PF anchor cleared"

    for label, operation in (
        ("capture", cleanup_capture),
        ("DNS", cleanup_dns),
        ("PF", cleanup_firewall),
    ):
        try:
            action = operation()
            if action:
                actions.append(action)
        except (
            IcprError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            errors.append(f"{label} cleanup failed: {exc}")
    if errors:
        fail("cleanup incomplete: " + "; ".join(errors))
    return actions


def recorded_capture_stop(attempt_dir: Path) -> str:
    state_path = attempt_dir / "capture-state.json"
    if not state_path.is_file():
        fail("capture-state.json is absent; the capture stop time cannot be trusted")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("top level is not an object")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        fail(f"capture stop evidence is unreadable: {exc}")
    stopped = state.get("stopped_utc")
    parse_utc(stopped)
    return str(stopped)


def capture_filter(addresses: list[str]) -> str:
    if not addresses:
        fail("no IPv4 ingress candidates are available for a narrow capture")
    normalized = [str(ipaddress.IPv4Address(address)) for address in addresses]
    hosts = " or ".join(f"host {address}" for address in sorted(set(normalized)))
    return f"({hosts}) and (tcp port 443 or udp port 443)"


def _direct_capture_candidate_sources(metadata: dict[str, Any]) -> dict[str, set[str]]:
    """Return only candidates directly evidenced by one attempt.

    ``approved_ingress_candidates`` and ``capture_recent_candidates`` are
    deliberately excluded: both contain inherited capture scope and therefore
    cannot be treated as fresh evidence for another attempt.
    """

    candidates: dict[str, set[str]] = {}

    def add(value: Any, source: str) -> None:
        try:
            address = str(ipaddress.IPv4Address(value))
        except (ipaddress.AddressValueError, TypeError):
            return
        candidates.setdefault(address, set()).add(source)

    for field in (
        "dns_ingress_candidates",
        "macos_effective_ingress_candidates",
    ):
        values = metadata.get(field)
        if not isinstance(values, (list, tuple, set)):
            continue
        for value in values:
            add(value, field)

    effective_dns = metadata.get("effective_dns")
    if isinstance(effective_dns, dict):
        hostnames = effective_dns.get("hostnames")
        if isinstance(hostnames, dict):
            for hostname, records in hostnames.items():
                if not isinstance(records, dict):
                    continue
                answers = records.get("A")
                if not isinstance(answers, list):
                    continue
                for answer in answers:
                    if isinstance(answer, dict):
                        add(
                            answer.get("address"),
                            f"effective_dns.hostnames.{hostname}.A",
                        )
        lookups = effective_dns.get("lookups")
        if isinstance(lookups, dict):
            for hostname, lookup in lookups.items():
                if not isinstance(lookup, dict):
                    continue
                values = lookup.get("ipv4")
                if not isinstance(values, list):
                    continue
                for value in values:
                    add(value, f"effective_dns.lookups.{hostname}.ipv4")
    return candidates


def recent_capture_candidate_evidence(
    day: str,
    *,
    lookback_days: int,
    client_root: Path | None = None,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Return recent directly evidenced candidates and compact provenance.

    Private Relay can retain an ingress tunnel across Safari launches, sessions,
    and UTC-day boundaries after the DNS pool changes. The capture therefore
    reuses exact resolver-observed candidates from finalized
    attempts in the current and configured previous UTC days. It never reuses a
    prior attempt's already-expanded capture union, so the lookback remains
    bounded. It does not use the ECS scanner or broaden capture to arbitrary
    HTTPS destinations.
    """

    if lookback_days < 0:
        fail("capture.recent_candidate_lookback_days must not be negative")
    try:
        current_day = dt.date.fromisoformat(day)
    except ValueError as exc:
        fail(f"invalid capture-candidate UTC date: {day}: {exc}")

    root = client_root or (EXPERIMENT_ROOT / "client")
    evidence: dict[str, dict[str, Any]] = {}
    for offset in range(lookback_days + 1):
        candidate_day = (current_day - dt.timedelta(days=offset)).isoformat()
        for metadata_path in sorted((root / candidate_day).glob("*/metadata.json")):
            if not (metadata_path.parent / "manifest.sha256").is_file():
                continue
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(metadata, dict):
                continue
            attempt_id = str(metadata.get("run_id") or metadata_path.parent.name)
            for address, sources in _direct_capture_candidate_sources(metadata).items():
                item = evidence.setdefault(
                    address,
                    {
                        "address": address,
                        "source_fields": set(),
                        "supporting_attempt_ids": set(),
                        "attempt_dates_utc": set(),
                    },
                )
                item["source_fields"].update(sources)
                item["supporting_attempt_ids"].add(attempt_id)
                item["attempt_dates_utc"].add(candidate_day)

    addresses = sorted(evidence, key=ipaddress.IPv4Address)
    provenance = [
        {
            "address": address,
            "source_fields": sorted(evidence[address]["source_fields"]),
            "supporting_attempt_ids": sorted(
                evidence[address]["supporting_attempt_ids"]
            ),
            "attempt_dates_utc": sorted(evidence[address]["attempt_dates_utc"]),
        }
        for address in addresses
    ]
    return addresses, provenance


def recent_capture_candidates(
    day: str,
    *,
    lookback_days: int,
    client_root: Path | None = None,
) -> list[str]:
    """Compatibility wrapper returning only recent candidate addresses."""

    candidates, _ = recent_capture_candidate_evidence(
        day,
        lookback_days=lookback_days,
        client_root=client_root,
    )
    return candidates


def start_capture(attempt_dir: Path, interface: str, bpf: str, snaplen: int) -> int:
    sudo_ready()
    capture_path = attempt_dir / "client.pcap"
    capture_path.touch(mode=0o600, exist_ok=False)
    capture_log = (attempt_dir / "capture.log").open("ab")
    process = subprocess.Popen(
        [
            "sudo",
            "-n",
            "/usr/sbin/tcpdump",
            "-i",
            interface,
            "-n",
            "-p",
            "-s",
            str(snaplen),
            "-U",
            "-w",
            str(capture_path),
            bpf,
        ],
        stdout=capture_log,
        stderr=subprocess.STDOUT,
    )
    time.sleep(1)
    if process.poll() is not None:
        fail(f"tcpdump failed to start; inspect {attempt_dir / 'capture.log'}")
    (attempt_dir / "capture.pid").write_text(f"{process.pid}\n", encoding="utf-8")
    write_json(
        attempt_dir / "capture-state.json",
        {
            "pid": process.pid,
            "process_group": None,
            "signal_scope": "pid",
            "capture_path": str(capture_path),
            "interface": interface,
            "filter": bpf,
            "started_utc": utc_now(),
        },
    )
    return process.pid


def validated_attempt_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    client_root = (EXPERIMENT_ROOT / "client").resolve()
    try:
        resolved.relative_to(client_root)
    except ValueError:
        fail(f"attempt path is outside the experiment client archive: {resolved}")
    if not (resolved / "metadata.json").is_file():
        fail(f"attempt metadata is absent: {resolved}")
    return resolved


def find_attempt(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_dir():
        return validated_attempt_directory(candidate)
    matches = list((EXPERIMENT_ROOT / "client").rglob(value))
    directories = [path for path in matches if path.is_dir()]
    if len(directories) != 1:
        fail(f"could not resolve exactly one attempt for {value!r}")
    return validated_attempt_directory(directories[0])


def acquire_lifecycle_lock(attempt_dir: Path) -> Any:
    lock_root = EXPERIMENT_ROOT / "runtime" / "locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / f"{attempt_dir.name}.lock"
    lock = lock_path.open("a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    except OSError:
        lock.close()
        raise
    return lock


def release_lifecycle_lock(lock: Any) -> None:
    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    lock.close()


def start_watchdog(attempt_dir: Path, deadline_utc: str) -> int:
    runtime = EXPERIMENT_ROOT / "runtime" / "watchdogs"
    runtime.mkdir(parents=True, exist_ok=True)
    log_path = runtime / f"{attempt_dir.name}.log"
    log_handle = log_path.open("ab")
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "_watchdog",
            str(attempt_dir),
            "--deadline-utc",
            deadline_utc,
        ],
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    log_handle.close()
    (attempt_dir / "watchdog.pid").write_text(f"{process.pid}\n", encoding="utf-8")
    return process.pid


def stop_watchdog(attempt_dir: Path) -> None:
    pid_path = attempt_dir / "watchdog.pid"
    if not pid_path.is_file():
        return
    pid = int(pid_path.read_text(encoding="utf-8").strip())
    if pid == os.getpid():
        pid_path.unlink(missing_ok=True)
        return
    if process_running(pid):
        command = process_command(pid)
        if "controller.py _watchdog" not in command or str(attempt_dir) not in command:
            fail(f"watchdog PID {pid} was reused; refusing to signal it")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while process_running(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        if process_running(pid):
            fail(f"watchdog process group {pid} did not stop")
    pid_path.unlink(missing_ok=True)


def dns_query_condition_changed(attempt_dir: Path) -> tuple[bool, list[int]]:
    query_log = attempt_dir / "dns-queries.jsonl"
    unsupported: set[int] = set()
    if query_log.is_file():
        for line in query_log.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                qtype = int(row.get("qtype", 0))
            except (json.JSONDecodeError, TypeError, ValueError):
                unsupported.add(-1)
                continue
            if qtype not in {1, 28}:
                unsupported.add(qtype)
    return bool(unsupported), sorted(unsupported)


def attempt_runtime_statuses() -> list[dict[str, Any]]:
    client_root = EXPERIMENT_ROOT / "client"
    marker_names = (
        "metadata.json",
        "events.jsonl",
        "manifest.sha256",
        "capture.pid",
        "capture-state.json",
        "watchdog.pid",
        "dns-pin-state.json",
        "firewall-state.json",
    )
    directories: set[Path] = set()
    for marker_name in marker_names:
        directories.update(path.parent for path in client_root.rglob(marker_name))

    statuses: list[dict[str, Any]] = []
    for attempt in sorted(directories):
        manifest = attempt / "manifest.sha256"
        metadata_path = attempt / "metadata.json"
        issues: list[str] = []
        metadata_error = None
        if not metadata_path.is_file():
            metadata_error = "metadata.json is absent"
            issues.append(metadata_error)
        else:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if not isinstance(metadata, dict):
                    raise ValueError("metadata top level is not an object")
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                metadata_error = str(exc)
                issues.append(f"metadata is unreadable: {exc}")
        if not manifest.is_file():
            issues.append("attempt is not hash-finalized")
        else:
            try:
                verify_attempt(attempt)
            except IcprError as exc:
                issues.append(f"finalized attempt integrity failure: {exc}")

        process_states: dict[str, Any] = {}
        for name in ("capture", "watchdog"):
            pid_path = attempt / f"{name}.pid"
            if not pid_path.is_file():
                continue
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
                running: bool | str = process_running(pid)
            except (OSError, ValueError):
                pid = None
                running = "unknown"
            process_states[name] = {"pid": pid, "running": running}
            issues.append(f"{name} PID state remains")

        capture_state_path = attempt / "capture-state.json"
        if capture_state_path.is_file():
            try:
                capture_state = json.loads(
                    capture_state_path.read_text(encoding="utf-8")
                )
                if not isinstance(capture_state, dict):
                    raise ValueError("top level is not an object")
                if not capture_state.get("stopped_utc"):
                    issues.append("capture state has no verified stop timestamp")
                else:
                    parse_utc(capture_state["stopped_utc"])
            except (IcprError, OSError, json.JSONDecodeError, ValueError) as exc:
                issues.append(f"capture state is unreadable: {exc}")

        for state_name, label in (
            ("dns-pin-state.json", "DNS resolver override"),
            ("firewall-state.json", "PF anchor"),
        ):
            state_path = attempt / state_name
            if not state_path.is_file():
                continue
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if not isinstance(state, dict):
                    raise ValueError("top level is not an object")
                restored = bool(state.get("restored_utc"))
                if restored:
                    parse_utc(state["restored_utc"])
            except (IcprError, OSError, json.JSONDecodeError, ValueError) as exc:
                restored = False
                issues.append(f"{label} state is unreadable: {exc}")
            if not restored:
                issues.append(f"{label} has not been restored")

        statuses.append(
            {
                "attempt": str(attempt),
                "finalized": manifest.is_file(),
                "metadata_error": metadata_error,
                "processes": process_states,
                "recovery_required": bool(issues),
                "issues": issues,
            }
        )
    return statuses


def recovery_required_attempts() -> list[dict[str, Any]]:
    return [row for row in attempt_runtime_statuses() if row["recovery_required"]]


def refuse_unfinished_attempts() -> None:
    unresolved = recovery_required_attempts()
    if not unresolved:
        return
    summary = "; ".join(
        f"{row['attempt']}: {', '.join(row['issues'])}" for row in unresolved
    )
    fail(
        "a prior attempt requires finish/abort/cleanup before another live attempt: "
        + summary
    )


def cmd_watchdog(args: argparse.Namespace) -> int:
    attempt_dir = validated_attempt_directory(Path(args.attempt))
    deadline = parse_utc(args.deadline_utc)
    while True:
        remaining = (deadline - dt.datetime.now(dt.timezone.utc)).total_seconds()
        if remaining <= 0:
            break
        refresh = subprocess.run(
            ["sudo", "-n", "-v"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if refresh.returncode != 0:
            print(
                "[icpr-step9] watchdog could not maintain the approved sudo "
                "timestamp; manual finish or cleanup is required: "
                + refresh.stderr.strip(),
                file=sys.stderr,
            )
            return 2
        time.sleep(min(remaining, 30))
    if (attempt_dir / "manifest.sha256").is_file():
        return 0
    lock = acquire_lifecycle_lock(attempt_dir)
    try:
        if (attempt_dir / "manifest.sha256").is_file():
            return 0
        config = load_json_yaml(CONFIG_PATH)
        metadata = json.loads(
            (attempt_dir / "metadata.json").read_text(encoding="utf-8")
        )
        finish_interface = active_interface()
        finish_software = software_snapshot()
        finish_network_time = _sudo(
            ["/usr/sbin/systemsetup", "-getusingnetworktime"]
        ).stdout.strip()
        automatic_changes = []
        if finish_interface != metadata.get("active_interface"):
            automatic_changes.append("active_interface")
        if network_type(finish_interface) != metadata.get("network_type"):
            automatic_changes.append("network_type")
        if finish_software.get("macos") != metadata.get("macos_version"):
            automatic_changes.append("macos_version")
        if finish_software.get("safari") != metadata.get("safari_version"):
            automatic_changes.append("safari_version")
        if "On" not in finish_network_time:
            automatic_changes.append("network_time")
        unsupported, qtypes = dns_query_condition_changed(attempt_dir)
        if unsupported:
            automatic_changes.append("unsupported_dns_query_type_during_pin")
        write_json(
            attempt_dir / "finish-condition.json",
            {
                "recorded_utc": utc_now(),
                "active_interface": finish_interface,
                "network_type": network_type(finish_interface),
                "software": finish_software,
                "network_time": finish_network_time,
                "operator_confirmation": "unavailable: automatic timeout",
                "automatic_changes": automatic_changes,
                "unsupported_dns_qtypes": qtypes,
            },
        )
        actions = cleanup_attempt(attempt_dir, config, noninteractive=True)
        capture_stopped = recorded_capture_stop(attempt_dir)
        append_jsonl(
            attempt_dir / "events.jsonl",
            {
                "event": "capture_stopped",
                "recorded_utc": capture_stopped,
                "source": "automatic_timeout_watchdog",
            },
        )
        append_jsonl(
            attempt_dir / "events.jsonl",
            {
                "event": "run_finished",
                "recorded_utc": utc_now(),
                "outcome": "timeout",
                "reason": "automatic operator-completion grace expired",
                "condition_changed": bool(automatic_changes),
                "automatic_condition_changes": automatic_changes,
                "unsupported_dns_qtypes": qtypes,
                "end_condition_confirmation": "unavailable: automatic timeout",
                "cleanup_actions": actions,
            },
        )
        stop_watchdog(attempt_dir)
        finalize_attempt(attempt_dir)
    finally:
        release_lifecycle_lock(lock)
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    config = load_json_yaml(Path(args.config))
    dependencies = dependency_status()
    interface = active_interface()
    recovery_status = attempt_runtime_statuses()
    try:
        pins = load_pins(Path(args.pins))
        pin_status: dict[str, Any] = {
            "ready": bool(pins["akamai"] and pins["apple_as714"]),
            "version": pins["version"],
            "akamai_count": len(pins["akamai"]),
            "apple_as714_count": len(pins["apple_as714"]),
        }
    except IcprError as exc:
        pin_status = {"ready": False, "error": str(exc)}
    current_software = software_snapshot()
    hosts_status = hosts_override_status(config)
    ipv6_route = ipv6_default_route_status()
    expected_software = config.get("software_versions", {})
    software_mismatches = [
        f"{key}: configured={expected_software.get(key)!r} current={current_software.get(key)!r}"
        for key in ("macos", "safari", "python")
        if expected_software.get(key) != current_software.get(key)
    ]
    report = {
        "recorded_utc": utc_now(),
        "dependencies": dependencies,
        "missing_dependencies": [name for name, item in dependencies.items() if not item["present"]],
        "software": current_software,
        "software_mismatches": software_mismatches,
        "active_interface": interface,
        "network_type": network_type(interface),
        "configuration_gaps": [
            *configuration_gaps(config),
            *privileged_configuration_blockers(config),
        ],
        "pins": pin_status,
        "hosts_override": hosts_status,
        "ipv6_default_route": ipv6_route,
        "attempt_runtime_state": recovery_status,
        "recovery_required": [
            row for row in recovery_status if row["recovery_required"]
        ],
        "privileged_capture_permission": "untested; prepare-run requests sudo explicitly",
        "dns_pinning": "temporary hosts CNAME-target override; plan-only until explicit approval",
        "targeted_firewall": "plan-only until explicit approval",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report["missing_dependencies"] and not report["recovery_required"] else 2


def existing_attempts() -> list[tuple[Path, dict[str, Any]]]:
    attempts: list[tuple[Path, dict[str, Any]]] = []
    for path in (EXPERIMENT_ROOT / "client").rglob("metadata.json"):
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"attempt metadata is unreadable and cannot be ignored: {path}: {exc}")
        if not isinstance(metadata, dict):
            fail(f"attempt metadata is not an object: {path}")
        attempts.append((path.parent, metadata))
    return attempts


def load_execution_plan(path_text: str, config_path: Path) -> tuple[dict[str, Any], str]:
    path = Path(path_text).expanduser().resolve()
    digest = verify_sidecar(path)
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"execution plan is unreadable: {path}: {exc}")
    if not isinstance(plan, dict):
        fail("execution plan top level must be an object")
    if plan.get("schema_version") != STATUS_SCHEMA_VERSION:
        fail(f"execution plan schema_version must be {STATUS_SCHEMA_VERSION}")
    if plan.get("document_type") not in {
        "rehearsal_execution_plan",
        "campaign_execution_plan",
    }:
        fail("execution plan document_type is invalid")
    if plan.get("status") != "frozen":
        fail("execution plan status must be frozen")
    run_mode = plan.get("run_mode")
    if plan.get("document_type") != f"{run_mode}_execution_plan":
        fail("execution plan document_type and run_mode do not agree")
    parse_utc(plan.get("created_utc"))
    try:
        dt.date.fromisoformat(str(plan.get("date_utc")))
    except ValueError as exc:
        fail(f"execution plan date_utc is invalid: {exc}")
    if plan.get("config_sha256") != sha256_file(config_path):
        fail("execution plan configuration hash does not match the selected configuration")
    if plan.get("controller_sha256") != controller_sha256():
        fail("execution plan controller hash does not match the current controller")
    if not re.fullmatch(r"[0-9a-f]{64}", str(plan.get("pin_list_sha256", ""))):
        fail("execution plan pin_list_sha256 is absent or invalid")
    expected_reference_inputs = reference_input_hashes(
        load_json_yaml(config_path), date_utc=str(plan.get("date_utc"))
    )
    if plan.get("reference_inputs") != expected_reference_inputs:
        fail("execution plan reference-input hashes differ from the current verified files")
    if not plan.get("campaign") or plan.get("session") not in {
        "morning",
        "daytime",
        "evening",
    }:
        fail("execution plan campaign or session is invalid")
    try:
        maximum_attempts = int(plan.get("maximum_attempts_per_slot"))
    except (TypeError, ValueError):
        maximum_attempts = 0
    if maximum_attempts < 1:
        fail("execution plan maximum_attempts_per_slot must be positive")
    if not isinstance(plan.get("slots"), list) or not plan["slots"]:
        fail("execution plan contains no concrete slots")
    required_slot_fields = {
        "slot_id",
        "sequence_number",
        "block_id",
        "attempt_number",
        "session",
        "private_relay_state",
        "location_setting",
        "ingress_group",
        "ingress_ip",
        "freshness_method",
        "fallback",
    }
    slot_ids = []
    for index, slot in enumerate(plan["slots"], start=1):
        if not isinstance(slot, dict) or not required_slot_fields.issubset(slot):
            fail(f"execution plan slot {index} is missing required fields")
        if slot.get("sequence_number") != index:
            fail("execution plan slot sequence numbers must be contiguous and one-based")
        if slot.get("session") != plan.get("session"):
            fail("execution plan slot session differs from the plan session")
        if not isinstance(slot.get("fallback"), bool):
            fail("execution plan slot fallback value must be Boolean")
        slot_ids.append(slot.get("slot_id"))
    if any(not isinstance(slot_id, str) or not slot_id for slot_id in slot_ids):
        fail("execution plan contains an empty or non-string slot ID")
    if len(slot_ids) != len(set(slot_ids)):
        fail("execution plan contains duplicate slot IDs")
    return plan, digest


def finalized_attempt_outcome(attempt_dir: Path) -> str:
    verify_attempt(attempt_dir)
    events_path = attempt_dir / "events.jsonl"
    try:
        lines = events_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"finalized attempt events are unreadable: {events_path}: {exc}")
    finished: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"finalized attempt events are malformed: {events_path}: {exc}")
        if event.get("event") == "run_finished":
            finished.append(event)
    if len(finished) != 1 or not finished[0].get("outcome"):
        fail(f"finalized attempt must contain exactly one run_finished outcome: {attempt_dir}")
    return str(finished[0]["outcome"])


def metadata_retry_number(metadata: dict[str, Any], path: Path) -> int:
    try:
        return int(metadata.get("retry_number", 1))
    except (TypeError, ValueError):
        fail(f"attempt has an invalid retry_number: {path}")


def slot_is_complete(
    slot_attempts: list[tuple[Path, dict[str, Any]]], maximum_retries: int
) -> bool:
    if not slot_attempts:
        return False
    outcomes: list[tuple[int, str]] = []
    for path, metadata in slot_attempts:
        retry = metadata_retry_number(metadata, path)
        outcomes.append((retry, finalized_attempt_outcome(path)))
    if any(outcome == "success" for _, outcome in outcomes):
        return True
    technical = {"error", "timeout", "prepare_error", "aborted"}
    return any(retry == maximum_retries and outcome in technical for retry, outcome in outcomes)


def validate_slot(
    args: argparse.Namespace, config: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    attempts = existing_attempts()
    maximum = int(config["timeout_and_retry"]["maximum_attempts_per_scheduled_slot"])
    if not 1 <= args.retry_number <= maximum:
        fail(f"--retry-number must be between 1 and {maximum}")
    duplicates = [
        path
        for path, metadata in attempts
        if metadata.get("campaign") == args.campaign
        and metadata.get("slot_id") == args.slot_id
        and metadata_retry_number(metadata, path) == args.retry_number
    ]
    if duplicates:
        fail(
            f"campaign/slot/retry already exists and will not be overwritten: {duplicates[0]}"
        )
    previous = [
        (path, metadata)
        for path, metadata in attempts
        if metadata.get("campaign") == args.campaign
        and metadata.get("slot_id") == args.slot_id
        and metadata_retry_number(metadata, path) == args.retry_number - 1
    ]
    if args.retry_number > 1:
        if len(previous) != 1:
            fail("retry requires exactly one finalized immediately preceding attempt")
        prior_outcome = finalized_attempt_outcome(previous[0][0])
        if prior_outcome not in {"error", "timeout", "prepare_error", "aborted"}:
            fail("retry is allowed only after a finalized technical failure, timeout, or abort")

    plan = None
    plan_hash = None
    if args.execution_plan:
        plan, plan_hash = load_execution_plan(args.execution_plan, Path(args.config))
        if plan.get("campaign") != args.campaign:
            fail(
                f"execution plan campaign mismatch: plan={plan.get('campaign')!r} "
                f"command={args.campaign!r}"
            )
        if plan.get("run_mode") != args.mode:
            fail(
                f"execution plan mode mismatch: plan={plan.get('run_mode')!r} "
                f"command={args.mode!r}"
            )
        if plan.get("session") != args.session:
            fail(
                f"execution plan session mismatch: plan={plan.get('session')!r} "
                f"command={args.session!r}"
            )
        current_utc_date = dt.datetime.now(dt.timezone.utc).date().isoformat()
        if plan.get("date_utc") != current_utc_date:
            fail(
                f"execution plan is frozen for {plan.get('date_utc')}, "
                f"but the current UTC date is {current_utc_date}"
            )
        if int(plan.get("maximum_attempts_per_slot", 0)) != maximum:
            fail("execution plan retry limit does not match the selected configuration")
        if plan.get("pin_list_sha256") != sha256_file(Path(args.pins)):
            fail("execution plan pin-list hash does not match the selected pin file")
        contaminated = [
            path
            for path, metadata in attempts
            if metadata.get("campaign") == args.campaign
            and metadata.get("execution_plan_sha256") != plan_hash
        ]
        if contaminated:
            fail(
                "campaign contains attempts from a different or unrecorded execution plan: "
                f"{contaminated[0]}"
            )
        slots = plan["slots"]
        matches = [slot for slot in slots if slot.get("slot_id") == args.slot_id]
        if len(matches) != 1:
            fail(f"slot {args.slot_id!r} is absent or duplicated in the execution plan")
        slot = matches[0]
        normalized_ingress = (
            str(ipaddress.IPv4Address(args.ingress_ip)) if args.ingress_ip else None
        )
        expected = {
            "block_id": args.block_id,
            "attempt_number": args.attempt_number,
            "session": args.session,
            "private_relay_state": args.private_relay_state,
            "location_setting": args.location_setting,
            "ingress_group": args.ingress_group,
            "ingress_ip": normalized_ingress,
            "freshness_method": args.freshness_method,
            "fallback": bool(args.fallback),
        }
        for key, actual in expected.items():
            if slot.get(key) != actual:
                fail(f"execution slot mismatch for {key}: plan={slot.get(key)!r} command={actual!r}")
        attempts_by_slot: dict[str, list[tuple[Path, dict[str, Any]]]] = defaultdict(list)
        for path, metadata in attempts:
            if (
                metadata.get("campaign") == args.campaign
                and metadata.get("execution_plan_sha256") == plan_hash
            ):
                attempts_by_slot[str(metadata.get("slot_id"))].append((path, metadata))
        completed_slots = {
            slot_id
            for slot_id, slot_attempts in attempts_by_slot.items()
            if slot_is_complete(slot_attempts, maximum)
        }
        slot_index = next(index for index, value in enumerate(slots) if value["slot_id"] == args.slot_id)
        for earlier in slots[:slot_index]:
            if earlier["slot_id"] not in completed_slots:
                fail(f"execution-plan order violation; earlier slot is incomplete: {earlier['slot_id']}")
        later_ids = {value["slot_id"] for value in slots[slot_index + 1 :]}
        if set(attempts_by_slot) & later_ids:
            fail("cannot backfill an earlier slot after a later slot was finalized")
    elif args.mode in {"rehearsal", "campaign"}:
        fail(f"{args.mode} run requires a hash-verified execution plan")
    return plan, plan_hash


def validate_prepare(args: argparse.Namespace, config: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    require_safe_privileged_configuration(config)
    refuse_unfinished_attempts()
    hosts_status = hosts_override_status(config)
    if not hosts_status.get("baseline_clean"):
        fail(
            "live attempt refused because the baseline /etc/hosts contains an "
            "unmanaged Private Relay pin or cannot be inspected"
        )
    if args.mode in {"rehearsal", "campaign"}:
        current_utc_date = dt.datetime.now(dt.timezone.utc).date().isoformat()
        gates = gate_report(
            config,
            date_utc=current_utc_date,
            config_path=Path(args.config),
            pins_path=Path(args.pins),
        )
        blocked = [gate for gate in ("G1", "G2", "G3", "G4") if gates[gate]["status"] != "ready"]
        if blocked:
            fail(f"{args.mode} run refused; launch gates are not ready: {', '.join(blocked)}")
        if not args.execution_plan:
            fail(f"{args.mode} run requires --execution-plan")
        if args.mode == "campaign" and not gates["campaign_start_permitted"]:
            fail("campaign run refused; rehearsal completion and final freeze are not verified")
    if args.approve_live != LIVE_APPROVAL:
        fail(f"live attempt refused; pass --approve-live {LIVE_APPROVAL} only after review")
    if args.private_relay_state == "off_control" and args.approve_real_ip != REAL_IP_APPROVAL:
        fail(f"Private-Relay-off control requires --approve-real-ip {REAL_IP_APPROVAL}")
    if args.freshness_method in {"C", "D"} and args.approve_disruptive != DISRUPTIVE_APPROVAL:
        fail(
            f"freshness method {args.freshness_method} requires --approve-disruptive {DISRUPTIVE_APPROVAL}"
        )
    if args.freshness_method == "B":
        safari = subprocess.run(["pgrep", "-x", "Safari"], check=False, stdout=subprocess.DEVNULL)
        if safari.returncode == 0:
            fail("method B requires Safari to be fully quit before prepare-run")
    pins = None
    intended = None
    if args.ingress_group != "unpinned":
        pins = load_pins(Path(args.pins))
        if not args.ingress_ip:
            fail("a pinned run requires --ingress-ip")
        intended = str(ipaddress.IPv4Address(args.ingress_ip))
        if intended not in pins[args.ingress_group]:
            fail(
                f"{intended} is not in approved {args.ingress_group} list version {pins['version']}"
            )
        if args.approve_dns != DNS_APPROVAL:
            print(json.dumps(resolver_plan(config, intended), indent=2, sort_keys=True))
            fail(f"pinned run requires --approve-dns {DNS_APPROVAL} after reviewing this plan")
        if args.approve_disruptive != DISRUPTIVE_APPROVAL:
            print(json.dumps(resolver_plan(config, intended), indent=2, sort_keys=True))
            fail(
                "hosts-based pin activation requires --approve-disruptive "
                f"{DISRUPTIVE_APPROVAL} because it restarts networkserviceproxy"
            )
    if args.fallback and args.ingress_group == "unpinned":
        fail("targeted fallback requires a confirmed pinned ingress")
    if args.fallback and args.approve_firewall != FIREWALL_APPROVAL:
        interface = active_interface() or "<active-interface>"
        print(json.dumps(firewall_plan(config, intended or "<pin-ip>", interface), indent=2))
        fail(
            f"fallback requires --approve-firewall {FIREWALL_APPROVAL} after reviewing this plan"
        )
    return pins, intended


def _cmd_prepare_locked(args: argparse.Namespace) -> int:
    config = load_json_yaml(Path(args.config))
    pins, intended = validate_prepare(args, config)
    execution_plan, execution_plan_hash = validate_slot(args, config)
    run_id = generate_run_id()
    started = utc_now()
    day = started[:10]
    attempt_dir = EXPERIMENT_ROOT / "client" / day / run_id
    attempt_dir.mkdir(parents=True, exist_ok=False)
    interface = active_interface()
    if not interface:
        fail("no active default-route interface was detected")
    software = software_snapshot()
    if config.get("configuration_status") == "frozen":
        expected = config["software_versions"]
        mismatches = [
            key
            for key in ("macos", "safari", "python")
            if software.get(key) != expected.get(key)
        ]
        if mismatches:
            fail(f"frozen software condition differs for: {', '.join(mismatches)}")
    url = config["server"]["url_template"].format(run_id=run_id)
    metadata: dict[str, Any] = {
        "run_id": run_id,
        "campaign": args.campaign,
        "run_mode": args.mode,
        "session": args.session,
        "slot_id": args.slot_id,
        "retry_number": args.retry_number,
        "block_id": args.block_id,
        "attempt_number": args.attempt_number,
        "client_start_utc": started,
        "clock_status": args.clock_status,
        "private_relay_state": args.private_relay_state,
        "location_setting": args.location_setting,
        "intended_ingress_group": args.ingress_group,
        "intended_ingress_ip": intended,
        "pin_list_version": pins.get("version") if pins else None,
        "pin_list_sha256": (
            sha256_file(Path(args.pins)) if pins else None
        ),
        "approved_pin_group_addresses": pins.get(args.ingress_group, []) if pins else [],
        "quic_block_state": "targeted_ingress_udp_443" if args.fallback else "not_blocked",
        "hostname": config["server"]["hostname"],
        "url": url,
        "macos_version": software["macos"],
        "safari_version": software["safari"],
        "python_version": software["python"],
        "active_interface": interface,
        "network_type": args.network_type or network_type(interface),
        "real_public_ipv4": str(ipaddress.IPv4Address(args.real_public_ip)),
        "freshness_method": args.freshness_method,
        "ingress_attribution_policy": "bounded_candidate_contact_v2",
        "operator_condition_confirmation": args.condition_confirmation,
        "controller_version": config["software_versions"]["controller"],
        "config_version": config["config_version"],
        "config_sha256": sha256_file(Path(args.config)),
        "execution_plan_version": execution_plan.get("plan_version") if execution_plan else None,
        "execution_plan_sha256": execution_plan_hash,
    }
    write_json(attempt_dir / "metadata.json", metadata)
    append_jsonl(
        attempt_dir / "events.jsonl",
        {"event": "run_started", "recorded_utc": started, **metadata},
    )
    privileged_applied = False
    watchdog_started = False
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def interrupt_prepare(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt_prepare)
    try:
        sudo_ready()
        network_time = _sudo(["/usr/sbin/systemsetup", "-getusingnetworktime"]).stdout.strip()
        network_time_server = _sudo(
            ["/usr/sbin/systemsetup", "-getnetworktimeserver"]
        ).stdout.strip()
        clock_evidence = {
            "recorded_utc": utc_now(),
            "network_time": network_time,
            "network_time_server": network_time_server,
        }
        write_json(attempt_dir / "clock-status.json", clock_evidence)
        if "On" not in network_time:
            fail("macOS network time is not enabled")
        metadata["clock_evidence"] = clock_evidence
        before_dns = dig_snapshot(config["pinning"]["hostnames"])
        write_json(attempt_dir / "dns-before.json", before_dns)
        (
            recent_addresses,
            recent_candidate_provenance,
        ) = recent_capture_candidate_evidence(
            day,
            lookback_days=int(
                config["capture"].get("recent_candidate_lookback_days", 0)
            ),
        )
        if intended:
            # A pinned observation has one causal ingress candidate: the
            # configured pin.  Earlier versions also copied every recently
            # captured candidate into this filter, which made unrelated relay
            # traffic look like ingress ambiguity and produced false E04s.
            addresses = [intended]
            metadata["capture_candidate_scope"] = "intended_pin_only_v1"
        else:
            effective_dns = dig_snapshot(config["pinning"]["hostnames"])
            dns_addresses = all_ipv4_answers(effective_dns)
            macos_effective_dns, macos_effective_addresses = (
                macos_effective_resolver_snapshot(config)
            )
            write_json(attempt_dir / "dns-effective.json", macos_effective_dns)
            addresses = sorted(
                set(dns_addresses)
                | set(macos_effective_addresses)
                | set(recent_addresses),
                key=ipaddress.IPv4Address,
            )
            metadata["dns_ingress_candidates"] = dns_addresses
            metadata["macos_effective_ingress_candidates"] = (
                macos_effective_addresses
            )
            metadata["capture_candidate_scope"] = (
                "current_resolver_plus_bounded_direct_lookback_v1"
            )
        metadata["capture_recent_candidates"] = recent_addresses
        metadata["capture_recent_candidate_provenance"] = (
            recent_candidate_provenance
        )
        metadata["capture_recent_candidate_policy"] = (
            "direct_attempt_evidence_v1"
        )
        metadata["capture_recent_candidate_lookback_days"] = int(
            config["capture"].get("recent_candidate_lookback_days", 0)
        )
        metadata["approved_ingress_candidates"] = addresses
        bpf = capture_filter(addresses)
        metadata["capture_filter"] = bpf
        write_json(attempt_dir / "metadata.json", metadata)
        start_capture(
            attempt_dir,
            interface,
            bpf,
            int(config["capture"]["client_snaplen_bytes"]),
        )
        if args.fallback:
            privileged_applied = True
            apply_firewall(attempt_dir, config, intended or "", interface)
        if intended:
            privileged_applied = True
            pin_state = apply_dns_pin(attempt_dir, config, intended)
            effective_dns = {
                "recorded_utc": utc_now(),
                "mechanism": pin_state["mechanism"],
                "cname_target": pin_state["cname_target"],
                "target_lookup": pin_state["macos_effective_hosts_check"],
                "hostnames": {
                    hostname: {
                        "CNAME": [pin_state["cname_target"]],
                        "A": [{"address": intended, "source": "/etc/hosts"}],
                        "AAAA": [],
                    }
                    for hostname in config["pinning"]["hostnames"]
                },
            }
        write_json(attempt_dir / "dns-effective.json", effective_dns)
        metadata["effective_dns"] = effective_dns
        write_json(attempt_dir / "metadata.json", metadata)
        if args.freshness_method == "C":
            if not intended:
                sudo_ready()
                clear_networkserviceproxy_state()
            append_jsonl(
                attempt_dir / "events.jsonl",
                {
                    "event": "networkserviceproxy_restarted",
                    "recorded_utc": utc_now(),
                    "source": "pin_activation" if intended else "freshness_method_C",
                },
            )
        elif args.freshness_method == "D":
            append_jsonl(
                attempt_dir / "events.jsonl",
                {
                    "event": "private_relay_toggle_operator_confirmed",
                    "recorded_utc": utc_now(),
                    "confirmation": args.condition_confirmation,
                },
            )
        launch_requested = utc_now()
        response_timeout_seconds = int(
            config["timeout_and_retry"]["browser_response_timeout_seconds"]
        )
        response_deadline = (
            parse_utc(launch_requested)
            + dt.timedelta(seconds=response_timeout_seconds)
        ).isoformat().replace("+00:00", "Z")
        operator_grace_seconds = int(
            config["timeout_and_retry"]["operator_completion_grace_seconds"]
        )
        operator_deadline = (
            parse_utc(launch_requested)
            + dt.timedelta(seconds=operator_grace_seconds)
        ).isoformat().replace("+00:00", "Z")
        metadata["safari_launch_requested_utc"] = launch_requested
        metadata["timeout_deadline_utc"] = response_deadline
        metadata["operator_completion_deadline_utc"] = operator_deadline
        write_json(attempt_dir / "metadata.json", metadata)
        append_jsonl(
            attempt_dir / "events.jsonl",
            {
                "event": "safari_url_launch_requested",
                "recorded_utc": launch_requested,
                "url": url,
            },
        )
        start_watchdog(attempt_dir, operator_deadline)
        watchdog_started = True
        result = subprocess.run(["/usr/bin/open", "-a", "Safari", url], check=False)
        if result.returncode != 0:
            fail("Safari URL launch failed")
        append_jsonl(
            attempt_dir / "events.jsonl",
            {"event": "safari_url_opened", "recorded_utc": utc_now(), "url": url},
        )
    except BaseException as prepare_error:
        cleanup_succeeded = True
        recovery_lock = acquire_lifecycle_lock(attempt_dir)
        try:
            if privileged_applied or (attempt_dir / "capture.pid").exists():
                try:
                    cleanup_attempt(attempt_dir, config)
                except Exception as cleanup_error:
                    cleanup_succeeded = False
                    log(f"automatic cleanup also failed: {cleanup_error}")
            if cleanup_succeeded and watchdog_started:
                try:
                    stop_watchdog(attempt_dir)
                except Exception as watchdog_error:
                    cleanup_succeeded = False
                    log(f"automatic watchdog stop failed: {watchdog_error}")
            if cleanup_succeeded:
                if (attempt_dir / "capture-state.json").is_file():
                    append_jsonl(
                        attempt_dir / "events.jsonl",
                        {
                            "event": "capture_stopped",
                            "recorded_utc": recorded_capture_stop(attempt_dir),
                            "source": "prepare_error_cleanup",
                        },
                    )
                append_jsonl(
                    attempt_dir / "events.jsonl",
                    {
                        "event": "run_finished",
                        "recorded_utc": utc_now(),
                        "outcome": "prepare_error",
                        "reason": str(prepare_error),
                        "condition_changed": False,
                        "end_condition_confirmation": "unavailable: prepare failed",
                    },
                )
                try:
                    finalize_attempt(attempt_dir)
                except IcprError as finalize_error:
                    cleanup_succeeded = False
                    log(f"failed attempt could not be hash-finalized: {finalize_error}")
            else:
                append_jsonl(
                    attempt_dir / "events.jsonl",
                    {
                        "event": "prepare_error_detected",
                        "recorded_utc": utc_now(),
                        "reason": str(prepare_error),
                        "recovery_required": True,
                    },
                )
        finally:
            release_lifecycle_lock(recovery_lock)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    log(f"opened exactly one tagged Safari URL: {url}")
    log(f"attempt directory: {attempt_dir}")
    log(f"browser response-validity deadline: {response_deadline}")
    log(f"automatic operator-completion cleanup deadline: {operator_deadline}")
    log(
        "finish with: ./experiment/icpr finish-run "
        f"{run_id} --response-file /path/to/response.json "
        "--end-condition-confirmation '<conditions unchanged>'"
    )
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    global_lock = acquire_lifecycle_lock(Path("global-live-attempt"))
    try:
        return _cmd_prepare_locked(args)
    finally:
        release_lifecycle_lock(global_lock)


def finalize_pre_capture_abort(
    attempt_dir: Path,
    *,
    reason: str,
    condition_changed: bool,
    end_condition_confirmation: str,
) -> bool:
    """Finalize an operator-aborted attempt that never entered privileged setup."""
    if (attempt_dir / "manifest.sha256").is_file():
        return False
    pre_capture_forbidden = (
        "clock-status.json",
        "dns-before.json",
        "dns-effective.json",
        "dns-pin-state.json",
        "capture.pid",
        "capture-state.json",
        "firewall-state.json",
        "watchdog.pid",
    )
    if any((attempt_dir / name).exists() for name in pre_capture_forbidden):
        return False
    events_path = attempt_dir / "events.jsonl"
    try:
        events = [
            json.loads(line)
            for line in events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot inspect pre-capture attempt events: {exc}")
    if not events or events[0].get("event") != "run_started":
        return False
    if any(
        event.get("event")
        in {
            "capture_started",
            "safari_url_launch_requested",
            "safari_url_opened",
            "run_finished",
            "prepare_error_detected",
        }
        for event in events
    ):
        return False
    append_jsonl(
        events_path,
        {
            "event": "run_finished",
            "recorded_utc": utc_now(),
            "outcome": "aborted",
            "reason": reason,
            "condition_changed": condition_changed,
            "end_condition_confirmation": end_condition_confirmation,
            "cleanup_actions": [],
            "pre_capture_abort": True,
            "capture_started": False,
        },
    )
    finalize_attempt(attempt_dir)
    return True


def _finish(
    attempt_dir: Path,
    *,
    outcome: str,
    reason: str,
    response_file: str | None,
    condition_changed: bool,
    end_condition_confirmation: str,
) -> int:
    config = load_json_yaml(CONFIG_PATH)
    lock = acquire_lifecycle_lock(attempt_dir)
    try:
        metadata = json.loads(
            (attempt_dir / "metadata.json").read_text(encoding="utf-8")
        )
        if (attempt_dir / "manifest.sha256").exists():
            fail(f"attempt is already finalized: {attempt_dir}")
        if outcome == "aborted" and response_file is None:
            if finalize_pre_capture_abort(
                attempt_dir,
                reason=reason,
                condition_changed=condition_changed,
                end_condition_confirmation=end_condition_confirmation,
            ):
                log(f"retained and hash-finalized pre-capture abort: {attempt_dir}")
                return 0
        if response_file:
            response = json.loads(
                Path(response_file).expanduser().read_text(encoding="utf-8")
            )
            if response.get("run_id") != metadata["run_id"]:
                fail("response run_id does not match the attempt")
            write_json(attempt_dir / "response.json", response)
        elif outcome == "success":
            fail("a successful attempt requires --response-file with the returned JSON")
        sudo_ready()
        finish_interface = active_interface()
        finish_software = software_snapshot()
        finish_network_time = _sudo(
            ["/usr/sbin/systemsetup", "-getusingnetworktime"]
        ).stdout.strip()
        automatic_changes = []
        if finish_interface != metadata.get("active_interface"):
            automatic_changes.append("active_interface")
        if network_type(finish_interface) != metadata.get("network_type"):
            automatic_changes.append("network_type")
        if finish_software.get("macos") != metadata.get("macos_version"):
            automatic_changes.append("macos_version")
        if finish_software.get("safari") != metadata.get("safari_version"):
            automatic_changes.append("safari_version")
        if "On" not in finish_network_time:
            automatic_changes.append("network_time")
        unsupported_dns, unsupported_qtypes = dns_query_condition_changed(attempt_dir)
        if unsupported_dns:
            automatic_changes.append("unsupported_dns_query_type_during_pin")
        write_json(
            attempt_dir / "finish-condition.json",
            {
                "recorded_utc": utc_now(),
                "active_interface": finish_interface,
                "network_type": network_type(finish_interface),
                "software": finish_software,
                "network_time": finish_network_time,
                "operator_confirmation": end_condition_confirmation,
                "automatic_changes": automatic_changes,
                "unsupported_dns_qtypes": unsupported_qtypes,
            },
        )
        cleanup_actions = cleanup_attempt(attempt_dir, config)
        capture_stopped = recorded_capture_stop(attempt_dir)
        stop_watchdog(attempt_dir)
        append_jsonl(
            attempt_dir / "events.jsonl",
            {"event": "capture_stopped", "recorded_utc": capture_stopped},
        )
        append_jsonl(
            attempt_dir / "events.jsonl",
            {
                "event": "run_finished",
                "recorded_utc": utc_now(),
                "outcome": outcome,
                "reason": reason,
                "condition_changed": condition_changed or bool(automatic_changes),
                "automatic_condition_changes": automatic_changes,
                "unsupported_dns_qtypes": unsupported_qtypes,
                "end_condition_confirmation": end_condition_confirmation,
                "cleanup_actions": cleanup_actions,
            },
        )
        finalize_attempt(attempt_dir)
    finally:
        release_lifecycle_lock(lock)
    log(f"retained and hash-finalized {outcome} attempt: {attempt_dir}")
    return 0


def cmd_finish(args: argparse.Namespace) -> int:
    return _finish(
        find_attempt(args.attempt),
        outcome=args.outcome,
        reason=args.reason,
        response_file=args.response_file,
        condition_changed=args.condition_changed,
        end_condition_confirmation=args.end_condition_confirmation,
    )


def cmd_abort(args: argparse.Namespace) -> int:
    return _finish(
        find_attempt(args.attempt),
        outcome="aborted",
        reason=args.reason,
        response_file=None,
        condition_changed=args.condition_changed,
        end_condition_confirmation=args.end_condition_confirmation,
    )


def finalize_recovered_prepare_error(attempt: Path, cleanup_actions: list[str]) -> bool:
    """Finalize a prepare failure once its temporary system state is recovered."""
    if (attempt / "manifest.sha256").is_file():
        return False
    events_path = attempt / "events.jsonl"
    if not events_path.is_file():
        return False
    try:
        events = [
            json.loads(line)
            for line in events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot finalize recovered prepare failure: {exc}")
    if any(event.get("event") == "run_finished" for event in events):
        return False
    failures = [
        event for event in events if event.get("event") == "prepare_error_detected"
    ]
    if not failures:
        return False
    append_jsonl(
        events_path,
        {
            "event": "run_finished",
            "recorded_utc": utc_now(),
            "outcome": "prepare_error",
            "reason": failures[-1].get("reason", "prepare failed before the live attempt"),
            "condition_changed": False,
            "end_condition_confirmation": "unavailable: prepare failed before Safari launch",
            "cleanup_actions": cleanup_actions,
            "recovered_after_prepare_error": True,
        },
    )
    finalize_attempt(attempt)
    return True


def cmd_cleanup(args: argparse.Namespace) -> int:
    attempt = find_attempt(args.attempt)
    lock = acquire_lifecycle_lock(attempt)
    finalized = False
    try:
        actions = cleanup_attempt(attempt, load_json_yaml(CONFIG_PATH))
        stop_watchdog(attempt)
        finalized = finalize_recovered_prepare_error(attempt, actions)
    finally:
        release_lifecycle_lock(lock)
    log("cleanup complete: " + (", ".join(actions) if actions else "no active state found"))
    if finalized:
        log(f"retained and hash-finalized recovered prepare failure: {attempt}")
    return 0


def cmd_pin_plan(args: argparse.Namespace) -> int:
    config = load_json_yaml(Path(args.config))
    pins = load_pins(Path(args.pins))
    address = str(ipaddress.IPv4Address(args.ip))
    if address not in pins[args.group]:
        fail(f"{address} is not approved in {args.group} pin list {pins['version']}")
    print(json.dumps(resolver_plan(config, address), indent=2, sort_keys=True))
    return 0


def cmd_firewall_plan(args: argparse.Namespace) -> int:
    config = load_json_yaml(Path(args.config))
    pins = load_pins(Path(args.pins))
    address = str(ipaddress.IPv4Address(args.ip))
    if address not in pins[args.group]:
        fail(f"{address} is not approved in {args.group} pin list {pins['version']}")
    interface = args.interface or active_interface()
    if not interface:
        fail("no active interface detected")
    print(json.dumps(firewall_plan(config, address, interface), indent=2, sort_keys=True))
    return 0


def cmd_pilot(args: argparse.Namespace) -> int:
    config_path = Path(getattr(args, "config", CONFIG_PATH))
    config = load_json_yaml(config_path)
    attempts: list[tuple[dict[str, Any], str | None]] = []
    integrity_errors: list[str] = []
    for metadata_path in (EXPERIMENT_ROOT / "client").rglob("metadata.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            integrity_errors.append(f"unreadable attempt metadata {metadata_path}: {exc}")
            continue
        if not isinstance(metadata, dict):
            integrity_errors.append(f"attempt metadata is not an object: {metadata_path}")
            continue
        if metadata.get("run_mode") != "pilot":
            continue
        attempt = metadata_path.parent
        attempt_error = None
        try:
            verify_attempt(attempt)
        except IcprError as exc:
            attempt_error = str(exc)
            integrity_errors.append(f"pilot attempt integrity failure {attempt}: {exc}")
        attempts.append((metadata, attempt_error))

    paired: dict[str, dict[str, str]] = {}
    derived_errors: list[str] = []
    derived_files = [
        EXPERIMENT_ROOT / "derived" / "pairs_v1.csv",
        EXPERIMENT_ROOT / "derived" / "exclusions_v1.csv",
    ]
    for derived in derived_files:
        if not derived.is_file():
            derived_errors.append(f"derived pilot input is absent: {derived}")
            continue
        try:
            verify_sidecar(derived)
            with derived.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        except (IcprError, OSError, csv.Error) as exc:
            derived_errors.append(f"derived pilot input failed validation {derived}: {exc}")
            continue
        for row in rows:
            run_id = row.get("run_id")
            if not run_id:
                derived_errors.append(f"derived pilot row has no run_id: {derived}")
                continue
            if run_id in paired:
                derived_errors.append(f"pilot run_id appears in multiple derived rows: {run_id}")
                continue
            paired[run_id] = row

    def csv_truth(value: Any) -> bool:
        return str(value).strip().lower() in {"1", "true", "yes"}

    methods: dict[str, Counter[str]] = defaultdict(Counter)
    durations: dict[str, list[float]] = defaultdict(list)
    unrecognized_method_attempts = 0
    for metadata, attempt_error in attempts:
        method = metadata.get("freshness_method", "unknown")
        if method not in {"A", "B", "C", "D"}:
            unrecognized_method_attempts += 1
            integrity_errors.append(
                f"pilot attempt has invalid freshness_method: {metadata.get('run_id')}"
            )
            continue
        methods[method]["attempts"] += 1
        if attempt_error:
            methods[method]["integrity_invalid_attempts"] += 1
            continue
        row = paired.get(metadata["run_id"], {})
        if not row:
            methods[method]["unpaired_attempts"] += 1
            continue
        if row.get("disposition") == "accepted":
            methods[method]["fresh_accepted_connections"] += 1
            if row.get("client_start_utc") and row.get("client_end_utc"):
                try:
                    durations[method].append(
                        (
                            parse_utc(row["client_end_utc"])
                            - parse_utc(row["client_start_utc"])
                        ).total_seconds()
                    )
                except IcprError as exc:
                    methods[method]["integrity_invalid_attempts"] += 1
                    integrity_errors.append(
                        f"pilot duration timestamps are invalid for {metadata['run_id']}: {exc}"
                    )
        if row.get("exclusion_reason") == "E03_NO_FRESH_FLOW":
            methods[method]["no_fresh_flow"] += 1
        if csv_truth(row.get("reused_connection_proven")) or csv_truth(
            row.get("client_tunnel_reuse_proven")
        ):
            methods[method]["reused_connections"] += 1
        if row.get("exclusion_reason") == "E02_MULTIPLE_SERVER_CONNECTIONS":
            methods[method]["ambiguous_retries"] += 1
        if row.get("observed_ingress_ip") and row.get("exclusion_reason") not in {
            "E04_WRONG_OR_UNKNOWN_INGRESS",
            "E07_CLOCK_OR_LOG_CORRUPTION",
        }:
            methods[method]["ingress_observation_reliable"] += 1

    report = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "document_type": "freshness_pilot",
        "status": "incomplete",
        "recorded_utc": utc_now(),
        "config_sha256": sha256_file(config_path),
        "controller_sha256": controller_sha256(),
        "ordered_ladder": ["A", "B", "C", "D"],
        "methods": {},
        "selection_rule": "least disruptive method with at least the configured repeated fresh accepts and reliable ingress observation",
        "selected_method": None,
        "pilot_attempts_total": len(attempts),
        "unrecognized_method_attempts": unrecognized_method_attempts,
        "integrity_errors": integrity_errors,
        "derived_input_errors": derived_errors,
    }
    threshold = int(config["freshness"]["pilot_minimum_repeated_fresh_accepts"])
    for method in ("A", "B", "C", "D"):
        counts = methods[method]
        accepted = counts["fresh_accepted_connections"]
        report["methods"][method] = {
            "attempts": counts["attempts"],
            "fresh_accepted_connections": accepted,
            "reused_connections": counts["reused_connections"],
            "no_fresh_flow": counts["no_fresh_flow"],
            "ambiguous_retries": counts["ambiguous_retries"],
            "integrity_invalid_attempts": counts["integrity_invalid_attempts"],
            "unpaired_attempts": counts["unpaired_attempts"],
            "ingress_observation_reliable_count": counts[
                "ingress_observation_reliable"
            ],
            "ingress_observation_remained_reliable": bool(
                counts["attempts"]
                and counts["ingress_observation_reliable"] == counts["attempts"]
            ),
            "seconds_per_accepted_observation": (
                sum(durations[method]) / len(durations[method]) if durations[method] else None
            ),
        }
        method_clean = (
            counts["attempts"] > 0
            and counts["integrity_invalid_attempts"] == 0
            and counts["unpaired_attempts"] == 0
            and counts["ingress_observation_reliable"] == counts["attempts"]
        )
        if (
            report["selected_method"] is None
            and accepted >= threshold
            and method_clean
            and not integrity_errors
            and not derived_errors
        ):
            report["selected_method"] = method
    if report["selected_method"]:
        report["status"] = "passed"
    output = EXPERIMENT_ROOT / "reports" / "freshness_pilot_v2.json"
    write_json(output, report)
    output.with_name(output.name + ".sha256").unlink(missing_ok=True)
    write_sidecar(output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def cmd_pair(args: argparse.Namespace) -> int:
    pipeline = PairingPipeline(
        config_path=Path(args.config),
        client_root=Path(args.client_root) if args.client_root else None,
        server_root=Path(args.server_root) if args.server_root else None,
        feed_root=Path(args.feed_root) if args.feed_root else None,
        asn_path=Path(args.asn_file) if args.asn_file else None,
        operator_map_path=Path(args.operator_map) if args.operator_map else None,
    )
    records = pipeline.run()
    outputs = pipeline.write_outputs(records)
    counts = Counter(row["disposition"] for row in records)
    print(
        json.dumps(
            {
                "attempts": len(records),
                "accepted": counts["accepted"],
                "excluded": counts["excluded"],
                "pending": counts["pending"],
                "outputs": {name: str(path) for name, path in outputs.items()},
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_daily_report(args: argparse.Namespace) -> int:
    summary_path = EXPERIMENT_ROOT / "derived" / "daily_summary_v1.json"
    if not summary_path.is_file():
        fail("daily summary does not exist; run pair first")
    verify_sidecar(summary_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    eligibility_path = (
        EXPERIMENT_ROOT / "derived" / "objective_eligibility_summary_v1.json"
    )
    objective_summary: dict[str, Any] = {}
    if eligibility_path.is_file():
        verify_sidecar(eligibility_path)
        loaded = json.loads(eligibility_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            objective_summary = loaded
    if args.date:
        report = {
            "date": args.date,
            "strict_pairing": summary.get("days", {}).get(args.date, {}),
            "objective_eligibility": objective_summary.get("days", {}).get(
                args.date, {}
            ),
            "pipeline_version": summary.get("pipeline_version"),
            "interpretation": (
                "Strict pairing governs exact ingress-egress claims; objective-specific "
                "eligibility preserves independent destination and location evidence."
            ),
        }
    else:
        report = {
            "strict_pairing": summary,
            "objective_eligibility": objective_summary,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def dated_asn_gaps(rows: list[dict[str, str]], date: str | None = None) -> dict[str, Any]:
    """Summarize unresolved dated ASN mappings without changing evidence."""

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("pending_reason") != "dated_asn_mapping_missing":
            continue
        observation_date = str(
            row.get("apple_feed_date")
            or row.get("server_time_utc", "")[:10]
            or row.get("client_start_utc", "")[:10]
        )
        if date is not None and observation_date != date:
            continue
        entry = grouped.setdefault(
            observation_date,
            {
                "pending_observations": 0,
                "run_ids": [],
                "observed_ingress_ipv4": set(),
                "server_egress_ipv4": set(),
            },
        )
        entry["pending_observations"] += 1
        if row.get("run_id"):
            entry["run_ids"].append(str(row["run_id"]))
        for field, output_field in (
            ("observed_ingress_ip", "observed_ingress_ipv4"),
            ("server_remote_ip", "server_egress_ipv4"),
        ):
            value = str(row.get(field, "")).strip()
            if not value:
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == 4:
                entry[output_field].add(str(address))

    serializable: dict[str, dict[str, Any]] = {}
    for observation_date, entry in sorted(grouped.items()):
        serializable[observation_date] = {
            "pending_observations": entry["pending_observations"],
            "run_ids": sorted(entry["run_ids"]),
            "observed_ingress_ipv4": sorted(
                entry["observed_ingress_ipv4"], key=ipaddress.ip_address
            ),
            "server_egress_ipv4": sorted(
                entry["server_egress_ipv4"], key=ipaddress.ip_address
            ),
        }
    return {
        "status": "gaps" if serializable else "ready",
        "date_filter": date,
        "pending_observations": sum(
            entry["pending_observations"] for entry in serializable.values()
        ),
        "days": serializable,
    }


def cmd_asn_gaps(args: argparse.Namespace) -> int:
    pairs_path = Path(args.pairs)
    if not pairs_path.is_file():
        fail(f"pair output does not exist: {pairs_path}; run pair first")
    verify_sidecar(pairs_path)
    if args.date:
        try:
            dt.date.fromisoformat(args.date)
        except ValueError:
            fail("--date must use YYYY-MM-DD")
    with pairs_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    report = dated_asn_gaps(rows, args.date)
    report["pairs_path"] = str(pairs_path)
    report["pairs_sha256"] = sha256_file(pairs_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_empty and report["pending_observations"]:
        return 2
    return 0


def validate_status_document(
    path: Path,
    *,
    document_type: str,
    expected_status: str,
    config_hash: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        verify_sidecar(path)
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            fail("top level is not an object")
        if document.get("schema_version") != STATUS_SCHEMA_VERSION:
            fail(f"schema_version must be {STATUS_SCHEMA_VERSION}")
        if document.get("document_type") != document_type:
            fail(f"document_type must be {document_type}")
        if document.get("status") != expected_status:
            fail(f"status must be {expected_status}")
        parse_utc(document.get("recorded_utc"))
        if document.get("controller_sha256") != controller_sha256():
            fail("controller_sha256 does not match the current controller")
        if config_hash is not None and document.get("config_sha256") != config_hash:
            fail("config_sha256 does not match the selected configuration")
        checks = document.get("checks")
        required = GATE_REQUIRED_CHECKS[document_type]
        if not isinstance(checks, dict) or not required.issubset(checks):
            fail(f"checks must include: {', '.join(sorted(required))}")
        failed_checks = sorted(name for name, value in checks.items() if value is not True)
        if failed_checks:
            fail(f"checks are not all true: {', '.join(failed_checks)}")
        if document_type == "rehearsal_completion":
            plan_hash = str(document.get("execution_plan_sha256", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", plan_hash):
                fail("execution_plan_sha256 is required")
            plan_name = document.get("execution_plan_file")
            if not isinstance(plan_name, str) or Path(plan_name).name != plan_name:
                fail("execution_plan_file must be one filename in experiment/manifests")
            plan_path = EXPERIMENT_ROOT / "manifests" / plan_name
            verify_sidecar(plan_path)
            if sha256_file(plan_path) != plan_hash:
                fail("execution_plan_sha256 does not match the verified plan file")
        if document_type == "final_campaign_freeze" and not re.fullmatch(
            r"[0-9a-f]{64}", str(document.get("rehearsal_completion_sha256", ""))
        ):
            fail("rehearsal_completion_sha256 is required")
        return document, None
    except (IcprError, OSError, json.JSONDecodeError, KeyError) as exc:
        return None, str(exc)


def validate_pilot_report(
    path: Path, *, config_hash: str, minimum_accepts: int
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        verify_sidecar(path)
        report = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            fail("top level is not an object")
        if report.get("schema_version") != STATUS_SCHEMA_VERSION:
            fail(f"schema_version must be {STATUS_SCHEMA_VERSION}")
        if report.get("document_type") != "freshness_pilot":
            fail("document_type must be freshness_pilot")
        if report.get("status") != "passed":
            fail("status must be passed")
        parse_utc(report.get("recorded_utc"))
        if report.get("controller_sha256") != controller_sha256():
            fail("controller_sha256 does not match the current controller")
        if report.get("config_sha256") != config_hash:
            fail("config_sha256 does not match the selected configuration")
        if report.get("selected_method") not in {"A", "B", "C", "D"}:
            fail("selected_method is absent or invalid")
        if report.get("integrity_errors") or report.get("derived_input_errors"):
            fail("pilot report contains integrity or derived-input errors")
        selected = (report.get("methods") or {}).get(report["selected_method"])
        if not isinstance(selected, dict):
            fail("selected method accounting is absent")
        if selected.get("ingress_observation_remained_reliable") is not True:
            fail("selected method did not retain reliable ingress observation")
        if int(selected.get("integrity_invalid_attempts", -1)) != 0 or int(
            selected.get("unpaired_attempts", -1)
        ) != 0:
            fail("selected method contains invalid or unpaired attempts")
        if int(selected.get("fresh_accepted_connections", 0)) < minimum_accepts:
            fail("selected method does not meet the frozen minimum fresh-accept count")
        return report, None
    except (IcprError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, str(exc)


def reference_input_blockers(
    config: dict[str, Any], *, date_utc: str | None = None
) -> list[str]:
    blockers: list[str] = []
    mapping = config.get("mapping", {})
    asn_path = EXPERIMENT_ROOT / str(mapping.get("origin_asn_file", ""))
    operator_path = EXPERIMENT_ROOT / str(mapping.get("operator_map_file", ""))

    if not asn_path.is_file():
        blockers.append(f"user-supplied dated origin-ASN file is absent: {asn_path}")
    else:
        try:
            asn_rows, _asn_hash = _load_asn_rows(asn_path)
            if date_utc and not any(row.get("date") == date_utc for row in asn_rows):
                blockers.append(f"dated origin-ASN file has no rows for {date_utc}")
        except (IcprError, OSError) as exc:
            blockers.append(f"dated origin-ASN input failed hash/schema validation: {exc}")

    if not operator_path.is_file():
        blockers.append(f"versioned operator map is absent: {operator_path}")
    else:
        try:
            _load_operator_map(operator_path, mapping)
        except (IcprError, OSError) as exc:
            blockers.append(f"operator-map input failed hash/schema validation: {exc}")

    if date_utc:
        feed_dir = EXPERIMENT_ROOT / "feeds" / "apple" / date_utc
        feeds = sorted(feed_dir.glob("*.csv")) if feed_dir.is_dir() else []
        if len(feeds) != 1:
            blockers.append(
                f"exactly one user-supplied Apple egress CSV is required for {date_utc}"
            )
        else:
            try:
                verify_sidecar(feeds[0])
                _read_apple_feed(feeds[0])
            except (IcprError, OSError) as exc:
                blockers.append(f"Apple egress CSV failed hash/schema validation: {exc}")
    return blockers


def reference_input_hashes(
    config: dict[str, Any], *, date_utc: str
) -> dict[str, dict[str, str]]:
    blockers = reference_input_blockers(config, date_utc=date_utc)
    if blockers:
        fail("reference inputs are not ready: " + "; ".join(blockers))
    mapping = config["mapping"]
    asn_path = EXPERIMENT_ROOT / mapping["origin_asn_file"]
    operator_path = EXPERIMENT_ROOT / mapping["operator_map_file"]
    feeds = sorted((EXPERIMENT_ROOT / "feeds" / "apple" / date_utc).glob("*.csv"))
    paths = {
        "apple_egress_feed": feeds[0],
        "dated_origin_asn": asn_path,
        "operator_map": operator_path,
    }
    return {
        name: {
            "path": path.relative_to(EXPERIMENT_ROOT).as_posix(),
            "sha256": verify_sidecar(path),
        }
        for name, path in paths.items()
    }


def gate_report(
    config: dict[str, Any],
    *,
    date_utc: str | None = None,
    config_path: Path = CONFIG_PATH,
    pins_path: Path = PINS_PATH,
) -> dict[str, Any]:
    config_hash = sha256_file(config_path)
    gaps = [*configuration_gaps(config), *privileged_configuration_blockers(config)]
    dependencies = dependency_status()
    missing = [name for name, item in dependencies.items() if not item["present"]]
    try:
        pins = load_pins(pins_path)
        pins_ready = bool(pins["akamai"] and pins["apple_as714"])
        pins_problem = None
    except IcprError as exc:
        pins_ready = False
        pins_problem = str(exc)
    tests_marker = EXPERIMENT_ROOT / "manifests" / "synthetic-tests-v2.json"
    privileged_marker = EXPERIMENT_ROOT / "manifests" / "privileged-smoke-v2.json"
    pilot_report = EXPERIMENT_ROOT / "reports" / "freshness_pilot_v2.json"
    smoke_marker = EXPERIMENT_ROOT / "manifests" / "smoke-reconstruction-v2.json"

    tests_document, tests_problem = validate_status_document(
        tests_marker,
        document_type="synthetic_tests",
        expected_status="passed",
        config_hash=None,
    )
    privileged_document, privileged_problem = validate_status_document(
        privileged_marker,
        document_type="privileged_smoke",
        expected_status="passed",
        config_hash=config_hash,
    )
    smoke_document, smoke_problem = validate_status_document(
        smoke_marker,
        document_type="smoke_reconstruction",
        expected_status="passed",
        config_hash=config_hash,
    )
    pilot_document, pilot_problem = validate_pilot_report(
        pilot_report,
        config_hash=config_hash,
        minimum_accepts=int(config["freshness"]["pilot_minimum_repeated_fresh_accepts"]),
    )
    tests_ready = tests_document is not None
    privileged_ready = privileged_document is not None
    smoke_ready = smoke_document is not None
    pilot_selected = pilot_document is not None
    pilot_method = pilot_document.get("selected_method") if pilot_document else None
    configured_method = config.get("freshness", {}).get("selected_method")
    pilot_matches_config = pilot_selected and pilot_method == configured_method

    g2_blockers = [
        *[f"missing dependency: {name}" for name in missing],
        *(
            []
            if tests_ready
            else [f"synthetic test marker is absent or invalid: {tests_problem}"]
        ),
        *([] if pins_ready else [pins_problem or "both user-supplied approved pin groups must be populated"]),
        *reference_input_blockers(config, date_utc=date_utc),
    ]
    g3_blockers = [
        *(
            []
            if privileged_ready
            else [f"privileged smoke marker is absent or invalid: {privileged_problem}"]
        ),
        *(
            []
            if pilot_selected
            else [f"freshness pilot is absent or invalid: {pilot_problem}"]
        ),
        *(
            []
            if pilot_matches_config
            else ["freshness pilot selection is not frozen in the configuration"]
        ),
    ]
    g4_blockers = (
        []
        if smoke_ready
        else [f"smoke reconstruction marker is absent or invalid: {smoke_problem}"]
    )
    rehearsal_marker = EXPERIMENT_ROOT / "manifests" / "rehearsal-completion-v2.json"
    freeze_marker = EXPERIMENT_ROOT / "manifests" / "final-campaign-freeze-v2.json"
    rehearsal_document, rehearsal_problem = validate_status_document(
        rehearsal_marker,
        document_type="rehearsal_completion",
        expected_status="passed",
        config_hash=config_hash,
    )
    freeze_document, freeze_problem = validate_status_document(
        freeze_marker,
        document_type="final_campaign_freeze",
        expected_status="frozen",
        config_hash=config_hash,
    )
    rehearsal_ready = rehearsal_document is not None
    freeze_ready = freeze_document is not None
    if rehearsal_ready and freeze_ready:
        expected_rehearsal_hash = sha256_file(rehearsal_marker)
        if freeze_document.get("rehearsal_completion_sha256") != expected_rehearsal_hash:
            freeze_ready = False
            freeze_problem = "final freeze does not reference the verified rehearsal completion hash"

    report = {
        "G1": {
            "status": "ready" if not gaps else "blocked",
            "definition": config["launch_gates"]["G1"],
            "blockers": gaps,
        },
        "G2": {
            "status": "ready" if not g2_blockers else "blocked",
            "definition": config["launch_gates"]["G2"],
            "blockers": g2_blockers,
        },
        "G3": {
            "status": (
                "ready"
                if not g3_blockers
                else "untested"
                if not privileged_marker.exists() and not pilot_report.exists()
                else "blocked"
            ),
            "definition": config["launch_gates"]["G3"],
            "blockers": g3_blockers,
        },
        "G4": {
            "status": "ready" if smoke_ready else "untested" if not smoke_marker.exists() else "blocked",
            "definition": config["launch_gates"]["G4"],
            "blockers": g4_blockers,
        },
        "post_rehearsal": {
            "rehearsal_completion_verified": rehearsal_ready,
            "rehearsal_completion_problem": rehearsal_problem,
            "final_campaign_freeze_verified": freeze_ready,
            "final_campaign_freeze_problem": freeze_problem,
        },
    }
    report["campaign_start_permitted"] = bool(
        all(report[gate]["status"] == "ready" for gate in ("G1", "G2", "G3", "G4"))
        and rehearsal_ready
        and freeze_ready
    )
    return report


def schedule_parity(day: dt.date, anchor: dt.date) -> str:
    """Return the frozen alternation parity, including pre-anchor rehearsals."""
    return "odd" if (day - anchor).days % 2 == 0 else "even"


def cmd_rehearsal_check(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    pins_path = Path(args.pins)
    config = load_json_yaml(config_path)
    report = gate_report(config, config_path=config_path, pins_path=pins_path)
    if args.date or args.session or args.write_plan:
        if not args.date or not args.session:
            fail("--date and --session are required together for a rehearsal plan")
        try:
            day = dt.date.fromisoformat(args.date)
        except ValueError as exc:
            fail(f"invalid rehearsal UTC date: {args.date}: {exc}")
        report = gate_report(
            config,
            date_utc=args.date,
            config_path=config_path,
            pins_path=pins_path,
        )
        schedule = config["daily_schedule"]
        anchor_text = schedule.get("alternation_anchor_date_utc")
        if not anchor_text:
            fail("daily_schedule.alternation_anchor_date_utc must be frozen first")
        try:
            anchor = dt.date.fromisoformat(anchor_text)
        except ValueError as exc:
            fail(f"invalid alternation anchor UTC date: {anchor_text}: {exc}")
        pins = load_pins(pins_path)
        if not args.akamai_pin or not args.apple_pin:
            fail("a concrete rehearsal plan requires --akamai-pin and --apple-pin")
        try:
            selected_pins = {
                "akamai": str(ipaddress.IPv4Address(args.akamai_pin)),
                "apple_as714": str(ipaddress.IPv4Address(args.apple_pin)),
            }
        except ipaddress.AddressValueError as exc:
            fail(f"invalid rehearsal pin IPv4 address: {exc}")
        for group, address in selected_pins.items():
            if address not in pins[group]:
                fail(
                    f"rehearsal pin {address} is not in approved {group} list "
                    f"version {pins['version']}"
                )
        freshness_method = config.get("freshness", {}).get("selected_method")
        if freshness_method not in {"A", "B", "C", "D"}:
            fail("freshness.selected_method must be frozen before rendering a rehearsal plan")
        try:
            pinned_target = int(schedule["target_accepted_per_pinned_block"])
        except (KeyError, TypeError, ValueError):
            fail("daily_schedule.target_accepted_per_pinned_block must be a positive integer")
        if pinned_target < 1:
            fail("daily_schedule.target_accepted_per_pinned_block must be positive")
        parity = schedule_parity(day, anchor)
        order_key = f"pinned_order_on_{parity}_days"
        slots: list[dict[str, Any]] = []

        def add_slot(
            *, block_id: str, location: str, ingress_group: str, ingress_ip: str | None
        ) -> None:
            sequence_number = len(slots) + 1
            slots.append(
                {
                    "slot_id": (
                        f"{args.date.replace('-', '')}-{args.session}-"
                        f"{sequence_number:03d}"
                    ),
                    "sequence_number": sequence_number,
                    "block_id": block_id,
                    "attempt_number": sequence_number,
                    "session": args.session,
                    "private_relay_state": "on",
                    "location_setting": location,
                    "ingress_group": ingress_group,
                    "ingress_ip": ingress_ip,
                    "freshness_method": freshness_method,
                    "fallback": False,
                }
            )

        for item in schedule["unpinned_sequence"]:
            location = item["location"]
            block_id = (
                "unpinned-mgl"
                if location == "maintain_general_location"
                else "unpinned-ctz"
            )
            for _ in range(int(item["fresh_accepted_target"])):
                add_slot(
                    block_id=block_id,
                    location=location,
                    ingress_group="unpinned",
                    ingress_ip=None,
                )
        pinned_order = schedule[args.session][order_key]
        for block_id in pinned_order:
            definition = schedule["pinned_blocks"][block_id]
            group = definition["ingress_group"]
            for _ in range(pinned_target):
                add_slot(
                    block_id=block_id,
                    location=definition["location"],
                    ingress_group=group,
                    ingress_ip=selected_pins[group],
                )

        campaign = f"rehearsal-{args.date}-{args.session}-v1"
        gate_snapshot = json.loads(json.dumps(report))
        plan = {
            "schema_version": STATUS_SCHEMA_VERSION,
            "document_type": "rehearsal_execution_plan",
            "status": "frozen" if args.write_plan else "proposed",
            "plan_version": "v1",
            "created_utc": utc_now(),
            "campaign": campaign,
            "run_mode": "rehearsal",
            "date_utc": args.date,
            "session": args.session,
            "config_sha256": sha256_file(config_path),
            "controller_sha256": controller_sha256(),
            "pin_list_version": pins["version"],
            "pin_list_sha256": sha256_file(pins_path),
            "reference_inputs": reference_input_hashes(config, date_utc=args.date),
            "selected_pins": selected_pins,
            "maximum_attempts_per_slot": int(
                config["timeout_and_retry"]["maximum_attempts_per_scheduled_slot"]
            ),
            "maximum_duration_hours": 6,
            "stop_at_six_hours_even_if_slots_remain": True,
            "planned_session_duration_minutes": int(
                schedule["session_duration_minutes"]
            ),
            "stop_at_planned_session_limit_even_if_slots_remain": True,
            "inspect_results_during_session": False,
            "selective_backfill_forbidden": True,
            "slots": slots,
            "sequence": [
                *[
                    {
                        "phase": "unpinned",
                        "location_setting": item["location"],
                        "fresh_accepted_target": item["fresh_accepted_target"],
                    }
                    for item in schedule["unpinned_sequence"]
                ],
                *[
                    {
                        "phase": "pinned",
                        "block_id": block,
                        "target": pinned_target,
                        **schedule["pinned_blocks"][block],
                    }
                    for block in pinned_order
                ],
            ],
            "gate_snapshot": gate_snapshot,
        }
        report["proposed_rehearsal_plan"] = plan
        if args.write_plan:
            if any(
                report[gate]["status"] != "ready"
                for gate in ("G1", "G2", "G3", "G4")
            ):
                fail("cannot write a rehearsal execution plan until G1-G4 are ready")
            output = (
                EXPERIMENT_ROOT
                / "manifests"
                / f"rehearsal-plan-{args.date}-{args.session}-v1.json"
            )
            sidecar_path = output.with_name(output.name + ".sha256")
            if output.exists() or sidecar_path.exists():
                fail(f"refusing to overwrite an existing rehearsal plan: {output}")
            write_json(output, plan, immutable=True)
            sidecar = write_sidecar(output)
            report["plan_written"] = str(output)
            report["plan_sha256"] = sha256_file(output)
            report["plan_sidecar"] = str(sidecar)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight", help="read-only dependency and configuration check")
    preflight.add_argument("--config", default=str(CONFIG_PATH))
    preflight.add_argument("--pins", default=str(PINS_PATH))
    preflight.set_defaults(function=cmd_preflight)

    prepare = sub.add_parser("prepare-run", help="create one attempt and open one tagged Safari URL")
    prepare.add_argument("--config", default=str(CONFIG_PATH))
    prepare.add_argument("--pins", default=str(PINS_PATH))
    prepare.add_argument(
        "--mode", choices=["smoke", "pilot", "rehearsal", "campaign"], required=True
    )
    prepare.add_argument("--campaign", required=True)
    prepare.add_argument(
        "--session",
        choices=["morning", "daytime", "evening", "adhoc"],
        required=True,
    )
    prepare.add_argument("--slot-id", required=True)
    prepare.add_argument("--retry-number", type=int, default=1)
    prepare.add_argument("--execution-plan")
    prepare.add_argument("--block-id", required=True)
    prepare.add_argument("--attempt-number", type=int, required=True)
    prepare.add_argument("--private-relay-state", choices=["off_control", "on"], required=True)
    prepare.add_argument(
        "--location-setting",
        choices=["maintain_general_location", "country_and_time_zone"],
        required=True,
    )
    prepare.add_argument("--ingress-group", choices=["unpinned", "akamai", "apple_as714"], required=True)
    prepare.add_argument("--ingress-ip")
    prepare.add_argument("--real-public-ip", required=True)
    prepare.add_argument("--network-type")
    prepare.add_argument("--clock-status", choices=["synchronized"], required=True)
    prepare.add_argument("--freshness-method", choices=["A", "B", "C", "D"], required=True)
    prepare.add_argument("--condition-confirmation", required=True)
    prepare.add_argument("--fallback", action="store_true")
    prepare.add_argument("--approve-live")
    prepare.add_argument("--approve-real-ip")
    prepare.add_argument("--approve-dns")
    prepare.add_argument("--approve-firewall")
    prepare.add_argument("--approve-disruptive")
    prepare.set_defaults(function=cmd_prepare)

    finish = sub.add_parser("finish-run", help="finish, clean up, retain, and hash an attempt")
    finish.add_argument("attempt")
    finish.add_argument("--outcome", choices=["success", "error", "timeout"], default="success")
    finish.add_argument("--reason", default="operator completed attempt")
    finish.add_argument("--response-file")
    finish.add_argument("--condition-changed", action="store_true")
    finish.add_argument("--end-condition-confirmation", required=True)
    finish.set_defaults(function=cmd_finish)

    abort = sub.add_parser("abort-run", help="abort but retain and hash an attempt")
    abort.add_argument("attempt")
    abort.add_argument("--reason", required=True)
    abort.add_argument("--condition-changed", action="store_true")
    abort.add_argument("--end-condition-confirmation", required=True)
    abort.set_defaults(function=cmd_abort)

    cleanup = sub.add_parser("cleanup", help="restore temporary capture, DNS, and PF state")
    cleanup.add_argument("attempt")
    cleanup.set_defaults(function=cmd_cleanup)

    pin = sub.add_parser("pin-plan", help="show the approved DNS pin mechanism without applying it")
    pin.add_argument("--config", default=str(CONFIG_PATH))
    pin.add_argument("--pins", default=str(PINS_PATH))
    pin.add_argument("--group", choices=["akamai", "apple_as714"], required=True)
    pin.add_argument("--ip", required=True)
    pin.set_defaults(function=cmd_pin_plan)

    firewall = sub.add_parser("firewall-plan", help="show the targeted PF rule without applying it")
    firewall.add_argument("--config", default=str(CONFIG_PATH))
    firewall.add_argument("--pins", default=str(PINS_PATH))
    firewall.add_argument("--group", choices=["akamai", "apple_as714"], required=True)
    firewall.add_argument("--ip", required=True)
    firewall.add_argument("--interface")
    firewall.set_defaults(function=cmd_firewall_plan)

    pilot = sub.add_parser("pilot", help="regenerate the freshness pilot report")
    pilot.add_argument("--config", default=str(CONFIG_PATH))
    pilot.set_defaults(function=cmd_pilot)

    pair = sub.add_parser("pair", help="pair only hash-verified client and server evidence")
    pair.add_argument("--config", default=str(CONFIG_PATH))
    pair.add_argument("--client-root")
    pair.add_argument("--server-root")
    pair.add_argument("--feed-root")
    pair.add_argument("--asn-file")
    pair.add_argument("--operator-map")
    pair.set_defaults(function=cmd_pair)

    daily = sub.add_parser("daily-report", help="show versioned daily counts")
    daily.add_argument("--date")
    daily.set_defaults(function=cmd_daily_report)

    asn_gaps = sub.add_parser(
        "asn-gaps", help="report unresolved dated ASN mappings from pair output"
    )
    asn_gaps.add_argument("--date")
    asn_gaps.add_argument(
        "--pairs", default=str(EXPERIMENT_ROOT / "derived" / "pairs_v1.csv")
    )
    asn_gaps.add_argument(
        "--require-empty",
        action="store_true",
        help="exit 2 when unresolved dated ASN mappings remain",
    )
    asn_gaps.set_defaults(function=cmd_asn_gaps)

    rehearsal = sub.add_parser("rehearsal-check", help="evaluate G1-G4 without starting a rehearsal")
    rehearsal.add_argument("--config", default=str(CONFIG_PATH))
    rehearsal.add_argument("--pins", default=str(PINS_PATH))
    rehearsal.add_argument("--date")
    rehearsal.add_argument("--session", choices=["morning", "daytime", "evening"])
    rehearsal.add_argument("--akamai-pin")
    rehearsal.add_argument("--apple-pin")
    rehearsal.add_argument("--write-plan", action="store_true")
    rehearsal.set_defaults(function=cmd_rehearsal_check)

    watchdog = sub.add_parser("_watchdog", help=argparse.SUPPRESS)
    watchdog.add_argument("attempt")
    watchdog.add_argument("--deadline-utc", required=True)
    watchdog.set_defaults(function=cmd_watchdog)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.function(args))
    except IcprError as exc:
        print(f"[icpr-step9] ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[icpr-step9] interrupted; cleanup was attempted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
