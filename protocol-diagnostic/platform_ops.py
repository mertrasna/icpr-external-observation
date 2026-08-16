"""Safety-scoped macOS operations for the isolated iCPR protocol diagnostic."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "experiment"))

from icprlib import IcprError, utc_now, write_json  # noqa: E402


def fail(message: str) -> None:
    raise IcprError(message)


def sudo_ready(*, noninteractive: bool = False) -> None:
    command = ["sudo", "-n", "-v"] if noninteractive else ["sudo", "-v"]
    if subprocess.run(command, check=False).returncode != 0:
        fail("sudo authentication was not approved")


def sudo_run(
    argv: list[str], *, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
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


def sudo_bytes(argv: list[str]) -> bytes:
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


def active_interface() -> str | None:
    result = subprocess.run(
        ["/sbin/route", "-n", "get", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def ipv6_default_route_status() -> dict[str, Any]:
    result = subprocess.run(
        ["/sbin/route", "-n", "get", "-inet6", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    combined = (result.stdout + result.stderr).lower()
    # macOS route(8) can report an absent IPv6 default route with the
    # authoritative text below while still returning zero. Match the message
    # exactly as the established campaign controller does.
    absent = (
        "not in table" in combined
        or "no such process" in combined
        or "route has not been found" in combined
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "present": result.returncode == 0 and not absent,
        "confirmed_absent": absent,
    }


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


def render_hosts_override(
    content: bytes, targets: list[str] | str, pin_ip: str, comment: str
) -> bytes:
    ipaddress.IPv4Address(pin_ip)
    if isinstance(targets, str):
        targets = [targets]
    if not targets or len(targets) != len(set(targets)):
        fail("diagnostic pin hostname set is empty or contains duplicates")
    for target in targets:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", target):
            fail(f"diagnostic pin hostname is invalid: {target}")
        if hosts_target_entries(content, target):
            fail(f"baseline /etc/hosts already contains an unmanaged entry for {target}")
    separator = b"" if not content or content.endswith(b"\n") else b"\n"
    return content + separator + f"{pin_ip}\t{' '.join(targets)}\t# {comment}\n".encode()


def dscacheutil_addresses(output: str) -> tuple[list[str], list[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        value = value.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if key.strip() in {"ip_address", "ipv4_address"} and address.version == 4:
            ipv4.add(str(address))
        elif key.strip() == "ipv6_address" and address.version == 6:
            ipv6.add(str(address))
    return sorted(ipv4, key=ipaddress.ip_address), sorted(ipv6, key=ipaddress.ip_address)


def clear_networkserviceproxy_state() -> dict[str, Any]:
    result = subprocess.run(
        ["sudo", "-n", "/usr/bin/killall", "networkserviceproxy"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    combined = (result.stdout + result.stderr).lower()
    absent = "no matching process" in combined
    if result.returncode != 0 and not absent:
        fail(
            "privileged command failed: /usr/bin/killall networkserviceproxy: "
            + result.stderr.strip()
        )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": "already_absent" if absent else "terminated",
    }


def apply_dns_pin(attempt_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    pinning = config["pinning"]
    pin_ip = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    target = str(pinning["cname_target"])
    direct_hostnames = [str(value) for value in pinning.get("direct_hostnames", [target])]
    if target not in direct_hostnames:
        fail("diagnostic direct pin set omits the shared CNAME target")
    hosts_path = str(pinning["hosts_file"])
    if hosts_path != "/etc/hosts" or target != "mask.apple-dns.net":
        fail("diagnostic pinning configuration is outside the approved hosts/CNAME scope")
    sudo_ready()
    if subprocess.run(["sudo", "-n", "test", "-L", hosts_path], check=False).returncode == 0:
        fail(f"refusing to replace hosts symlink: {hosts_path}")
    if subprocess.run(["sudo", "-n", "test", "-f", hosts_path], check=False).returncode != 0:
        fail(f"refusing to replace missing or non-regular hosts file: {hosts_path}")
    previous = sudo_bytes(["/bin/cat", hosts_path])
    for name in direct_hostnames:
        if hosts_target_entries(previous, name):
            fail(f"baseline {hosts_path} already contains an unmanaged entry for {name}")
    stat_fields = sudo_run(["/usr/bin/stat", "-f", "%u %g %Lp", hosts_path]).stdout.split()
    applied = render_hosts_override(
        previous, direct_hostnames, pin_ip, str(pinning["temporary_comment"])
    )
    baseline_path = attempt_dir / "hosts.baseline"
    applied_path = attempt_dir / "hosts.applied"
    baseline_path.write_bytes(previous)
    applied_path.write_bytes(applied)
    os.chmod(baseline_path, 0o600)
    os.chmod(applied_path, 0o600)
    state: dict[str, Any] = {
        "mechanism": "hosts_cname_override_protocol_diagnostic_v1",
        "applied_utc": utc_now(),
        "pin_ip": pin_ip,
        "hosts_path": hosts_path,
        "cname_target": target,
        "pinned_hostnames": direct_hostnames,
        "hosts_previous_base64": base64.b64encode(previous).decode("ascii"),
        "hosts_applied_base64": base64.b64encode(applied).decode("ascii"),
        "hosts_uid": int(stat_fields[0]),
        "hosts_gid": int(stat_fields[1]),
        "hosts_mode": stat_fields[2],
    }
    state_path = attempt_dir / "dns-pin-state.json"
    state["hosts_install_started_utc"] = utc_now()
    write_json(state_path, state)
    sudo_run(
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
    sudo_run(["/usr/bin/dscacheutil", "-flushcache"])
    sudo_run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
    state["networkserviceproxy_activation"] = clear_networkserviceproxy_state()
    state["networkserviceproxy_state_cleared_utc"] = utc_now()
    ipv6_route = ipv6_default_route_status()
    effective_names = direct_hostnames
    effective_lookups: dict[str, Any] = {}
    for name in effective_names:
        effective = subprocess.run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", str(name)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        ipv4, ipv6 = dscacheutil_addresses(effective.stdout)
        effective_lookups[str(name)] = {
            "returncode": effective.returncode,
            "stdout": effective.stdout,
            "stderr": effective.stderr,
            "ipv4": ipv4,
            "ipv6": ipv6,
        }
    state["effective_lookup"] = effective_lookups[target]
    state["effective_hostname_lookups"] = effective_lookups
    state["ipv6_default_route"] = ipv6_route
    write_json(state_path, state)
    for name, lookup in effective_lookups.items():
        if lookup["returncode"] != 0 or set(lookup["ipv4"]) != {pin_ip}:
            fail(f"macOS effective lookup for {name} did not return only the approved pin")
        if lookup["ipv6"] and not ipv6_route["confirmed_absent"]:
            fail(
                f"IPv6 answers exist for {name} and absence of an IPv6 default route was not confirmed"
            )
    return state


def render_pf_rule(config: dict[str, Any], interface: str) -> str:
    pin = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    ipaddress.IPv4Address(pin)
    if not re.fullmatch(r"[A-Za-z0-9._-]+", interface):
        fail("active interface contains unsupported characters")
    label = str(config["firewall"]["label"])
    if not re.fullmatch(r"[A-Za-z0-9._-]+", label):
        fail("PF label contains unsupported characters")
    return (
        f"block drop out quick on {interface} inet proto udp "
        f"from any to {pin} port = 443 label \"{label}\""
    )


def validate_rendered_pf_rule(rule: str, config: dict[str, Any], interface: str) -> None:
    expected = render_pf_rule(config, interface)
    if rule.strip() != expected:
        fail("PF rule differs from the exact frozen diagnostic rule")
    origin = str(config["server"]["public_ipv4"])
    pin = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    if pin == origin:
        fail("refusing a PF rule that targets the controlled origin")
    forbidden = (" proto tcp ", " from any to any ", f" to {origin} ")
    if any(fragment in f" {rule} " for fragment in forbidden):
        fail("PF rule scope is broader than the frozen diagnostic target")


def pf_rule_statistics(snapshot: str) -> dict[str, int]:
    statistics: dict[str, int] = {}
    for key in ("Evaluations", "Packets", "Bytes", "States"):
        match = re.search(rf"\b{key}:\s*([0-9]+)\b", snapshot)
        if match:
            statistics[key.lower()] = int(match.group(1))
    return statistics


def system_validate_pf_rule(rule: str) -> dict[str, Any]:
    sudo_ready()
    result = subprocess.run(
        ["sudo", "-n", "/sbin/pfctl", "-vnf", "-"],
        input=rule + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "valid": result.returncode == 0,
    }


def prepare_firewall(
    attempt_dir: Path,
    config: dict[str, Any],
    *,
    condition: str,
    interface: str,
) -> dict[str, Any]:
    if condition not in {"udp_permitted", "udp_blocked"}:
        fail("unknown diagnostic firewall condition")
    firewall = config["firewall"]
    anchor = str(firewall["anchor"])
    if anchor != "com.apple/icpr-protocol-diagnostic-v1":
        fail("PF anchor is outside the dedicated diagnostic anchor")
    sudo_ready()
    previous = sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip()
    if previous:
        fail(f"dedicated diagnostic PF anchor is not empty: {anchor}")
    status = sudo_run(["/sbin/pfctl", "-s", "info"]).stdout
    was_enabled = "Status: Enabled" in status
    state: dict[str, Any] = {
        "condition": condition,
        "anchor": anchor,
        "interface": interface,
        "pf_was_enabled": was_enabled,
        "pf_enable_required": not was_enabled,
        "pf_enable_token": "",
        "previous_anchor_rules": previous,
        "exact_rule": "",
        "rule_loaded": False,
        "statistics_after_load": {},
        "prepared_utc": utc_now(),
    }
    state_path = attempt_dir / "firewall-state.json"
    write_json(state_path, state)
    if condition == "udp_permitted":
        state["loaded_rules_snapshot"] = ""
        state["statistics_after_load_utc"] = utc_now()
        write_json(state_path, state)
        return state

    rule = render_pf_rule(config, interface)
    validate_rendered_pf_rule(rule, config, interface)
    token = ""
    if not was_enabled:
        enable_output_path = attempt_dir / "pf-enable-output.txt"
        state["pf_enable_output_path"] = str(enable_output_path.resolve())
        state["pf_enable_started_utc"] = utc_now()
        write_json(state_path, state)
        enable_output_path.touch(mode=0o600, exist_ok=False)
        os.chmod(enable_output_path, 0o600)
        with enable_output_path.open("w", encoding="utf-8") as output_handle:
            enabled = subprocess.run(
                ["sudo", "-n", "/sbin/pfctl", "-E"],
                text=True,
                stdout=output_handle,
                stderr=subprocess.STDOUT,
                check=False,
            )
            output_handle.flush()
            os.fsync(output_handle.fileno())
        enable_output = enable_output_path.read_text(encoding="utf-8")
        state["pf_enable_returncode"] = enabled.returncode
        state["pf_enable_output"] = enable_output
        state["pf_enable_completed_utc"] = utc_now()
        write_json(state_path, state)
        if enabled.returncode != 0:
            fail(
                "privileged command failed: /sbin/pfctl -E: "
                + enable_output.strip()
            )
        matches = set(
            re.findall(
                r"Token\s*:\s*([1-9][0-9]*)", enable_output, re.IGNORECASE
            )
        )
        if len(matches) != 1:
            fail("PF enable token could not be recorded; manual recovery is required")
        token = next(iter(matches))
    state["pf_enable_token"] = token
    state["exact_rule"] = rule
    state["rule_load_started_utc"] = utc_now()
    write_json(state_path, state)
    sudo_run(["/sbin/pfctl", "-a", anchor, "-f", "-"], input_text=rule + "\n")
    state["rule_load_completed_utc"] = utc_now()
    write_json(state_path, state)
    loaded = sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip()
    # Persist the exact post-load state before validating it so cleanup can
    # still remove only this dedicated anchor after a verification failure.
    state["rule_loaded"] = bool(loaded)
    state["loaded_rules_snapshot"] = loaded
    write_json(state_path, state)
    required = (
        "block drop out quick",
        f"on {interface}",
        "inet proto udp",
        f"to {config['fixed_conditions']['intended_ingress_ipv4']}",
        "port = 443",
        f'label "{firewall["label"]}"',
    )
    lines = [line.strip() for line in loaded.splitlines() if line.strip()]
    if len(lines) != 1 or not all(fragment in lines[0] for fragment in required):
        fail("loaded PF anchor does not contain exactly the approved diagnostic rule")
    state["rule_loaded"] = True
    statistics_snapshot = sudo_run(
        ["/sbin/pfctl", "-a", anchor, "-vvs", "rules"]
    ).stdout.strip()
    state["statistics_after_load_utc"] = utc_now()
    state["statistics_after_load_snapshot"] = statistics_snapshot
    state["statistics_after_load"] = pf_rule_statistics(statistics_snapshot)
    pin = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    reset = sudo_run(["/sbin/pfctl", "-k", "0.0.0.0/0", "-k", pin])
    state["targeted_state_reset_utc"] = utc_now()
    state["targeted_state_reset_output"] = (reset.stdout + reset.stderr).strip()
    write_json(state_path, state)
    return state


def snapshot_firewall_before_cleanup(attempt_dir: Path) -> None:
    path = attempt_dir / "firewall-state.json"
    if not path.is_file():
        return
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("restored_utc"):
        return
    if state.get("anchor") != "com.apple/icpr-protocol-diagnostic-v1":
        fail("PF state names an anchor outside the diagnostic scope")
    snapshot = sudo_run(
        ["/sbin/pfctl", "-a", str(state["anchor"]), "-vvs", "rules"]
    ).stdout.strip()
    state["statistics_before_cleanup_utc"] = utc_now()
    state["statistics_before_cleanup_snapshot"] = snapshot
    state["statistics_before_cleanup"] = pf_rule_statistics(snapshot)
    write_json(path, state)


def capture_filter(addresses: list[str]) -> str:
    normalized = sorted(
        {str(ipaddress.IPv4Address(value)) for value in addresses},
        key=ipaddress.IPv4Address,
    )
    if not normalized:
        fail("diagnostic capture has no approved IPv4 candidates")
    hosts = " or ".join(f"host {value}" for value in normalized)
    return f"({hosts}) and (tcp port 443 or udp port 443)"


def capture_command(
    capture_path: Path, interface: str, bpf: str, snaplen: int
) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", interface):
        fail("capture interface contains unsupported characters")
    if not isinstance(snaplen, int) or snaplen <= 0:
        fail("capture snap length must be a positive integer")
    return [
        "sudo",
        "-n",
        "/usr/bin/nohup",
        "/usr/sbin/tcpdump",
        "-i",
        interface,
        "-n",
        "-p",
        "-s",
        str(snaplen),
        "-U",
        "-w",
        str(capture_path.resolve()),
        bpf,
    ]


def capture_command_variants(argv: list[str]) -> set[str]:
    if argv[:4] != ["sudo", "-n", "/usr/bin/nohup", "/usr/sbin/tcpdump"]:
        fail("capture command is outside the approved tcpdump scope")
    return {" ".join(argv), " ".join(argv[2:]), " ".join(argv[3:])}


def matching_capture_pids(expected_commands: set[str]) -> dict[int, str]:
    result = subprocess.run(
        ["/bin/ps", "-ww", "-axo", "pid=,command="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("could not inspect processes for diagnostic capture recovery")
    matches: dict[int, str] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*([0-9]+)\s+(.*)$", line)
        if match and match.group(2) in expected_commands:
            matches[int(match.group(1))] = match.group(2)
    return matches


def start_capture(attempt_dir: Path, interface: str, bpf: str, snaplen: int) -> int:
    sudo_ready()
    capture_path = attempt_dir / "client.pcap"
    capture_path.touch(mode=0o600, exist_ok=False)
    argv = capture_command(capture_path, interface, bpf, snaplen)
    state_path = attempt_dir / "capture-state.json"
    state: dict[str, Any] = {
        "pid": None,
        "capture_path": str(capture_path.resolve()),
        "interface": interface,
        "filter": bpf,
        "snaplen": snaplen,
        "command_argv": argv,
        "launch_prepared_utc": utc_now(),
    }
    # This record must exist before tcpdump can start.  If the controller is
    # interrupted between Popen and PID persistence, cleanup can identify only
    # a process whose complete command line exactly matches this attempt.
    write_json(state_path, state)
    log_handle = (attempt_dir / "capture.log").open("ab")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
    finally:
        log_handle.close()
    state["launcher_pid"] = process.pid
    state["spawned_utc"] = utc_now()
    write_json(state_path, state)
    time.sleep(1)
    if process.poll() is not None:
        state["launch_failed_utc"] = utc_now()
        state["launch_returncode"] = process.returncode
        write_json(state_path, state)
        fail(f"tcpdump failed to start; inspect {attempt_dir / 'capture.log'}")
    matches = matching_capture_pids(capture_command_variants(argv))
    tcpdump_command = " ".join(argv[3:])
    tcpdump_pids = sorted(pid for pid, command in matches.items() if command == tcpdump_command)
    if len(tcpdump_pids) != 1:
        state["launch_failed_utc"] = utc_now()
        state["launch_exact_processes"] = matches
        write_json(state_path, state)
        fail("tcpdump launch did not produce exactly one attributable capture child")
    state["pid"] = tcpdump_pids[0]
    state["launch_exact_processes"] = matches
    (attempt_dir / "capture.pid").write_text(f"{tcpdump_pids[0]}\n", encoding="utf-8")
    state["started_utc"] = utc_now()
    write_json(state_path, state)
    return tcpdump_pids[0]


def process_running(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def process_command(pid: int) -> str:
    return subprocess.run(
        ["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()


def stop_capture(attempt_dir: Path, *, noninteractive: bool = False) -> str | None:
    pid_path = attempt_dir / "capture.pid"
    state_path = attempt_dir / "capture-state.json"
    if not pid_path.is_file() and not state_path.is_file():
        return None
    if not state_path.is_file():
        fail("capture PID exists without capture-state.json")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    expected = str((attempt_dir / "client.pcap").resolve())
    if state.get("capture_path") != expected:
        fail("capture state does not match the expected attempt capture")
    try:
        expected_argv = capture_command(
            Path(expected),
            str(state["interface"]),
            str(state["filter"]),
            int(state["snaplen"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"capture state cannot reconstruct the exact command: {exc}")
    if state.get("command_argv") != expected_argv:
        fail("capture state command differs from the exact diagnostic command")
    expected_commands = capture_command_variants(expected_argv)

    recorded_pids: set[int] = set()
    state_pid = state.get("pid")
    if state_pid is not None:
        if not isinstance(state_pid, int) or state_pid <= 1:
            fail("capture state PID is malformed")
        recorded_pids.add(state_pid)
    if pid_path.is_file():
        pid_text = pid_path.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9]+", pid_text):
            fail("capture PID is malformed")
        recorded_pids.add(int(pid_text))
    if len(recorded_pids) > 1:
        fail("capture PID artifacts disagree")

    matches = matching_capture_pids(expected_commands)
    for pid in recorded_pids:
        if process_running(pid) and matches.get(pid) not in expected_commands:
            fail("capture PID was reused; refusing to signal it")
    if len(matches) > 1:
        wrapper_command = " ".join(expected_argv)
        child_command = " ".join(expected_argv[3:])
        wrapper_pids = {
            pid for pid, command in matches.items() if command == wrapper_command
        }
        child_pids = {
            pid for pid, command in matches.items() if command == child_command
        }
        # macOS sudo uses one or two monitor/wrapper processes around the
        # command. Permit only that observed bounded tree: one durable,
        # recorded tcpdump child and one or two exact sudo wrappers, all bound
        # byte-for-byte to this attempt's unique capture path.
        if (
            len(matches) not in {2, 3}
            or len(recorded_pids) != 1
            or recorded_pids != child_pids
            or len(child_pids) != 1
            or len(wrapper_pids) not in {1, 2}
            or len(wrapper_pids | child_pids) != len(matches)
        ):
            fail("multiple exact diagnostic capture processes found; refusing ambiguity")
    if (
        state.get("started_utc")
        and not state.get("stopped_utc")
        and not matches
        and recorded_pids
        and not any(process_running(pid) for pid in recorded_pids)
    ):
        # The capture was confirmed running after launch but exited before the
        # controller requested a stop. This is objective retryable evidence loss,
        # not a network outcome.
        state["premature_exit_detected_utc"] = utc_now()
        write_json(state_path, state)
    matching_pids = sorted(matches)
    if matching_pids:
        if recorded_pids and not recorded_pids.issubset(matches):
            fail("exact capture process does not match the recorded PID")
        if not recorded_pids:
            state["pid_discovered_during_cleanup"] = matching_pids[0]
            state["pid_discovered_utc"] = utc_now()
            write_json(state_path, state)
        sudo_ready(noninteractive=noninteractive)
        state["exact_capture_pids_signalled"] = matching_pids
        write_json(state_path, state)
        for pid in reversed(matching_pids):
            result = subprocess.run(
                ["sudo", "-n", "/bin/kill", "-INT", str(pid)], check=False
            )
            if result.returncode != 0 and process_running(pid):
                fail("capture process could not be signalled")
        deadline = time.monotonic() + 10
        while any(process_running(pid) for pid in matching_pids) and time.monotonic() < deadline:
            time.sleep(0.2)
        if any(process_running(pid) for pid in matching_pids):
            fail("capture process did not stop")
    state.setdefault("stopped_utc", utc_now())
    write_json(state_path, state)
    pid_path.unlink(missing_ok=True)
    return "client capture stopped"


def restore_dns(attempt_dir: Path, *, noninteractive: bool = False) -> str | None:
    path = attempt_dir / "dns-pin-state.json"
    if not path.is_file():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    previous = base64.b64decode(state["hosts_previous_base64"], validate=True)
    applied = base64.b64decode(state["hosts_applied_base64"], validate=True)
    hosts_path = str(state["hosts_path"])
    if hosts_path != "/etc/hosts" or state.get("cname_target") != "mask.apple-dns.net":
        fail("DNS state is outside the dedicated diagnostic scope")
    sudo_ready(noninteractive=noninteractive)
    if state.get("restored_utc"):
        if sudo_bytes(["/bin/cat", hosts_path]) != previous:
            fail("restored hosts file no longer matches the saved baseline")
        return None
    current = sudo_bytes(["/bin/cat", hosts_path])
    recorded_install = bool(state.get("hosts_installed_utc"))
    install_completed = recorded_install or current == applied
    pin_may_have_been_active = install_completed
    if current == applied and not recorded_install:
        # install(1) completed but the process was interrupted before its
        # completion marker. Exact byte equality makes this inference safe.
        state["hosts_install_inferred_utc"] = utc_now()
        write_json(path, state)
    elif current == previous and recorded_install:
        # A previous cleanup restored the exact baseline but was interrupted
        # before recording completion. Continue the cache/proxy cleanup.
        state["hosts_restore_inferred_utc"] = utc_now()
        write_json(path, state)
    elif current not in {previous, applied}:
        fail(
            "ambiguous conflict at /etc/hosts; refusing to overwrite a concurrent change"
        )
    if current == applied:
        baseline_path = attempt_dir / "hosts.baseline"
        if not baseline_path.is_file():
            fail("hosts baseline artifact is missing during cleanup")
        if baseline_path.read_bytes() != previous:
            fail("hosts baseline artifact differs from recorded state")
        sudo_run(
            [
                "/usr/bin/install",
                "-o",
                str(int(state["hosts_uid"])),
                "-g",
                str(int(state["hosts_gid"])),
                "-m",
                str(state["hosts_mode"]),
                str(baseline_path),
                hosts_path,
            ]
        )
        state["hosts_restored_utc"] = utc_now()
    if pin_may_have_been_active:
        sudo_run(["/usr/bin/dscacheutil", "-flushcache"])
        sudo_run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
        state["networkserviceproxy_cleanup"] = clear_networkserviceproxy_state()
    if sudo_bytes(["/bin/cat", hosts_path]) != previous:
        fail("hosts file does not match the saved baseline after cleanup")
    state["restored_utc"] = utc_now()
    write_json(path, state)
    return "previous /etc/hosts restored byte-for-byte"


def restore_firewall(attempt_dir: Path, *, noninteractive: bool = False) -> str | None:
    path = attempt_dir / "firewall-state.json"
    if not path.is_file():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    anchor = str(state.get("anchor"))
    if anchor != "com.apple/icpr-protocol-diagnostic-v1":
        fail("PF state names an anchor outside the diagnostic scope")
    sudo_ready(noninteractive=noninteractive)
    if state.get("restored_utc"):
        if sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip():
            fail("diagnostic PF anchor is no longer empty after recorded cleanup")
        return None
    enable_required = bool(
        state.get("pf_enable_required", not bool(state.get("pf_was_enabled")))
    )
    token_values: set[str] = set()
    recorded_token = str(state.get("pf_enable_token") or "")
    if recorded_token:
        if not re.fullmatch(r"[1-9][0-9]*", recorded_token):
            fail("PF enable token is malformed")
        token_values.add(recorded_token)
    enable_output_path = attempt_dir / "pf-enable-output.txt"
    recorded_output_path = state.get("pf_enable_output_path")
    if recorded_output_path and recorded_output_path != str(enable_output_path.resolve()):
        fail("PF enable output path is outside the diagnostic attempt")
    if enable_output_path.is_file():
        enable_output = enable_output_path.read_text(encoding="utf-8")
        recorded_output = state.get("pf_enable_output")
        if recorded_output is not None and recorded_output != enable_output:
            fail("PF enable output artifact differs from recorded state")
        found = re.findall(
            r"Token\s*:\s*([0-9]+)", enable_output, re.IGNORECASE
        )
        if len(set(found)) > 1:
            fail("PF enable output contains multiple tokens")
        token_values.update(found)
    if len(token_values) > 1:
        fail("PF enable token evidence disagrees")
    token = next(iter(token_values), "")
    enable_started = bool(state.get("pf_enable_started_utc"))
    if enable_required and enable_started and not token:
        fail("PF enable outcome is ambiguous because no enable token was captured")
    if enable_required and state.get("rule_load_started_utc") and not enable_started:
        fail("PF rule load began without a recorded PF enable operation")
    if not enable_required and token:
        fail("unexpected PF enable token when PF was already enabled")
    if state.get("pf_enable_release_started_utc") and not state.get(
        "pf_enable_reference_released_utc"
    ):
        fail("PF enable-token release outcome is ambiguous")

    current = sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip()
    loaded = str(state.get("loaded_rules_snapshot", "")).strip()
    if state.get("rule_loaded"):
        if current != loaded and not (
            not current and state.get("rules_clear_started_utc")
        ):
            fail("PF cleanup conflict; current diagnostic anchor differs from this attempt")
    elif current:
        exact_rule = str(state.get("exact_rule") or "").strip()
        if not state.get("rule_load_started_utc") or not exact_rule:
            fail("PF cleanup conflict; unexpected diagnostic anchor rules")
        normalized_current = " ".join(current.split())
        normalized_exact = " ".join(exact_rule.split())
        if normalized_current != normalized_exact:
            fail("PF rule-load outcome is ambiguous; anchor rule is not the exact rule")
        state["rule_loaded"] = True
        state["loaded_rules_snapshot"] = current
        state["rule_load_inferred_utc"] = utc_now()
        write_json(path, state)
    if current:
        state["rules_clear_started_utc"] = utc_now()
        write_json(path, state)
        sudo_run(["/sbin/pfctl", "-a", anchor, "-F", "rules"])
    if sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip():
        fail("diagnostic PF anchor is not empty after cleanup")
    state["rules_cleared_utc"] = utc_now()
    if token:
        state["pf_enable_token"] = token
        state["pf_enable_release_started_utc"] = utc_now()
        write_json(path, state)
        sudo_run(["/sbin/pfctl", "-X", token])
        state["pf_enable_reference_released_utc"] = utc_now()
    state["restored_utc"] = utc_now()
    write_json(path, state)
    return "dedicated diagnostic PF anchor cleared"


def cleanup_attempt(
    attempt_dir: Path, *, noninteractive: bool = False
) -> list[str]:
    actions: list[str] = []
    errors: list[str] = []
    for label, operation in (
        ("capture", lambda: stop_capture(attempt_dir, noninteractive=noninteractive)),
        ("PF counters", lambda: snapshot_firewall_before_cleanup(attempt_dir)),
        ("DNS", lambda: restore_dns(attempt_dir, noninteractive=noninteractive)),
        ("PF", lambda: restore_firewall(attempt_dir, noninteractive=noninteractive)),
    ):
        try:
            result = operation()
            if isinstance(result, str) and result:
                actions.append(result)
        except Exception as exc:  # cleanup must attempt every independent restoration
            errors.append(f"{label} cleanup failed: {exc}")
    if errors:
        fail("cleanup incomplete: " + "; ".join(errors))
    return actions
