"""Shared, standard-library-only helpers for the Step 9 controller."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


EXPERIMENT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_ROOT.parent
CONFIG_PATH = EXPERIMENT_ROOT / "config" / "experiment_config.yaml"
EXAMPLE_CONFIG_PATH = EXPERIMENT_ROOT / "config" / "experiment_config.example.yaml"
PINS_PATH = EXPERIMENT_ROOT / "config" / "ingress_pins.yaml"
PIPELINE_VERSION = "v1.3"
RUN_ID_RE = re.compile(r"^icpr-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
DNS_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)

REQUIRED_PAIR_FIELDS = [
    "run_id",
    "campaign",
    "block_id",
    "attempt_number",
    "client_start_utc",
    "client_end_utc",
    "server_time_utc",
    "clock_status",
    "private_relay_state",
    "location_setting",
    "intended_ingress_group",
    "intended_ingress_ip",
    "pin_contact_status",
    "observed_ingress_ip",
    "ingress_transport",
    "ingress_5tuple",
    "freshness_evidence",
    "server_remote_ip",
    "server_remote_port",
    "server_transport",
    "server_http_protocol",
    "server_flow_key",
    "response_status",
    "apple_feed_date",
    "apple_feed_hash",
    "matched_prefix",
    "advertised_country",
    "advertised_region",
    "advertised_city",
    "ingress_asn",
    "egress_asn",
    "ingress_operator",
    "egress_operator",
    "operator_map_version",
    "same_operator",
    "disclosure_class",
    "disposition",
    "exclusion_reason",
    "pipeline_version",
]


class IcprError(RuntimeError):
    """A controlled error suitable for an operator-facing message."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_utc(value: str) -> dt.datetime:
    if not value or not isinstance(value, str):
        raise IcprError("missing UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise IcprError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise IcprError(f"timestamp is not explicitly UTC: {value}")
    return parsed.astimezone(dt.timezone.utc)


def epoch_to_utc(value: float | str) -> str:
    return (
        dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def load_json_yaml(path: Path) -> dict[str, Any]:
    """Load a JSON-compatible YAML 1.2 document without a YAML dependency."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IcprError(f"required file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IcprError(f"{path} must remain JSON-compatible YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise IcprError(f"top level of {path} must be an object")
    return value


def write_json(path: Path, value: Any, *, immutable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    if immutable:
        path.chmod(0o440)


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sidecar(path: Path) -> Path:
    sidecar = path.with_name(path.name + ".sha256")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{sidecar.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{sha256_file(path)}  {path.name}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, sidecar)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    sidecar.chmod(0o440)
    return sidecar


def verify_sidecar(path: Path) -> str:
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.is_file():
        raise IcprError(f"SHA-256 sidecar missing: {sidecar}")
    fields = sidecar.read_text(encoding="utf-8").split()
    if (
        len(fields) != 2
        or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0])
        or fields[1] != path.name
    ):
        raise IcprError(f"invalid SHA-256 sidecar: {sidecar}")
    expected = fields[0].lower()
    actual = sha256_file(path)
    if actual != expected:
        raise IcprError(f"SHA-256 mismatch: {path}")
    return actual


def finalize_attempt(attempt_dir: Path) -> None:
    manifest = attempt_dir / "manifest.sha256"
    if manifest.exists():
        raise IcprError(f"attempt is already finalized: {attempt_dir}")
    files = sorted(
        path
        for path in attempt_dir.rglob("*")
        if path.is_file()
        and path.name not in {"capture.pid", "manifest.sha256", "manifest.sha256.sha256"}
        and not path.name.endswith(".sha256")
    )
    if not files:
        raise IcprError(f"attempt contains no raw artifacts: {attempt_dir}")
    lines = []
    for path in files:
        relative = path.relative_to(attempt_dir)
        lines.append(f"{sha256_file(path)}  {relative.as_posix()}\n")
        path.chmod(0o440)
    manifest.write_text("".join(lines), encoding="utf-8")
    manifest.chmod(0o440)
    write_sidecar(manifest)
    attempt_dir.chmod(0o550)


def verify_attempt(attempt_dir: Path) -> dict[str, str]:
    manifest = attempt_dir / "manifest.sha256"
    verify_sidecar(manifest)
    verified: dict[str, str] = {}
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", raw_line)
        if not match:
            raise IcprError(f"invalid attempt manifest line: {raw_line!r}")
        expected, relative_text = match.groups()
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            raise IcprError(f"unsafe manifest path: {relative_text}")
        artifact = attempt_dir / relative
        if not artifact.is_file():
            raise IcprError(f"manifest artifact missing: {artifact}")
        actual = sha256_file(artifact)
        if actual != expected.lower():
            raise IcprError(f"attempt artifact hash mismatch: {artifact}")
        verified[relative.as_posix()] = actual
    actual_files = {
        path.relative_to(attempt_dir).as_posix()
        for path in attempt_dir.rglob("*")
        if path.is_file()
        and path.name not in {"manifest.sha256", "manifest.sha256.sha256", "capture.pid"}
        and not path.name.endswith(".sha256")
    }
    if actual_files != set(verified):
        unlisted = sorted(actual_files - set(verified))
        missing = sorted(set(verified) - actual_files)
        raise IcprError(
            f"attempt manifest is not closed over raw artifacts; unlisted={unlisted} missing={missing}"
        )
    return verified


def run_command(
    argv: list[str], *, check: bool = True, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise IcprError(f"command failed: {' '.join(argv)}: {exc}") from exc


def dependency_status() -> dict[str, dict[str, Any]]:
    commands = {
        "python3": "Python controller",
        "tcpdump": "narrow client packet capture",
        "tshark": "offline packet parsing",
        "dig": "DNS answers and TTL",
        "scutil": "default route/interface discovery",
        "networksetup": "network-service metadata",
        "dscacheutil": "effective macOS resolver check",
        "pfctl": "targeted fallback helper",
        "open": "one Safari URL launch",
        "sw_vers": "macOS version",
        "shasum": "operator-side hash inspection",
    }
    return {
        name: {
            "purpose": purpose,
            "path": shutil.which(name),
            "present": shutil.which(name) is not None,
        }
        for name, purpose in commands.items()
    }


def active_interface() -> str | None:
    route = subprocess.run(
        ["/sbin/route", "-n", "get", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    for line in route.stdout.splitlines():
        if line.strip().startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return None


def network_type(interface: str | None) -> str:
    if not interface:
        return "unknown"
    listing = subprocess.run(
        ["/usr/sbin/networksetup", "-listallhardwareports"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout
    blocks = listing.split("\n\n")
    for block in blocks:
        if f"Device: {interface}" not in block:
            continue
        if "Wi-Fi" in block:
            return "wifi"
        if "Ethernet" in block or "Thunderbolt" in block:
            return "ethernet"
        return "other"
    return "unknown"


def software_snapshot() -> dict[str, str | None]:
    macos = subprocess.run(
        ["/usr/bin/sw_vers", "-productVersion"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()
    build = subprocess.run(
        ["/usr/bin/sw_vers", "-buildVersion"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()
    safari = subprocess.run(
        [
            "/usr/bin/defaults",
            "read",
            "/Applications/Safari.app/Contents/Info",
            "CFBundleShortVersionString",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.strip()
    return {
        "macos": f"{macos} ({build})" if macos else None,
        "safari": safari or None,
        "python": platform.python_version(),
    }


def dig_snapshot(hostnames: Iterable[str], *, server: str | None = None, port: int | None = None) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"recorded_utc": utc_now(), "hostnames": {}}
    for hostname in hostnames:
        host_data: dict[str, list[dict[str, Any]]] = {"A": [], "AAAA": []}
        for record_type in ("A", "AAAA"):
            argv = ["dig"]
            if server:
                argv.append(f"@{server}")
            if port:
                argv.extend(["-p", str(port)])
            argv.extend([hostname, record_type, "+noall", "+answer"])
            result = subprocess.run(
                argv,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) >= 5 and fields[3] == record_type:
                    host_data[record_type].append(
                        {"address": fields[4], "ttl": int(fields[1])}
                    )
        snapshot["hostnames"][hostname] = host_data
    return snapshot


def all_ipv4_answers(snapshot: dict[str, Any]) -> list[str]:
    addresses: set[str] = set()
    for records in snapshot.get("hostnames", {}).values():
        for answer in records.get("A", []):
            try:
                addresses.add(str(ipaddress.IPv4Address(answer["address"])))
            except (ipaddress.AddressValueError, KeyError, TypeError):
                continue
    return sorted(addresses, key=ipaddress.ip_address)


def load_pins(path: Path = PINS_PATH) -> dict[str, Any]:
    verify_sidecar(path)
    pins = load_json_yaml(path)
    for group in ("akamai", "apple_as714"):
        values = pins.get(group)
        if not isinstance(values, list):
            raise IcprError(f"{path}: {group} must be a list")
        normalized = []
        for value in values:
            try:
                normalized.append(str(ipaddress.IPv4Address(value)))
            except ipaddress.AddressValueError as exc:
                raise IcprError(f"{path}: invalid {group} IPv4 address: {value}") from exc
        if len(normalized) != len(set(normalized)):
            raise IcprError(f"{path}: duplicate address in {group}")
        pins[group] = normalized
    overlap = set(pins["akamai"]) & set(pins["apple_as714"])
    if overlap:
        raise IcprError(f"{path}: ingress addresses cannot appear in both groups: {sorted(overlap)}")
    if not pins.get("version") or pins.get("version") == "REQUIRED":
        raise IcprError(f"{path}: a non-placeholder version is required")
    if not pins.get("verified_utc"):
        raise IcprError(f"{path}: verified_utc is required")
    parse_utc(pins["verified_utc"])
    return pins


def configuration_gaps(config: dict[str, Any]) -> list[str]:
    gaps: list[str] = []

    def add(message: str) -> None:
        if message not in gaps:
            gaps.append(message)

    if config.get("schema_version") != 1:
        add("schema_version must be 1")
    if config.get("time_basis") != "UTC":
        add("time_basis must be UTC")
    if config.get("primary_analysis_family") != "IPv4":
        add("primary_analysis_family must be IPv4")
    server = config.get("server", {})
    hostname = server.get("hostname") if isinstance(server, dict) else None
    hostname_is_valid = isinstance(hostname, str) and bool(
        DNS_HOSTNAME_RE.fullmatch(hostname)
    )
    if not hostname_is_valid:
        add("server.hostname must be a valid DNS hostname")
    expected_url = (
        f"https://{hostname}/probe/{{run_id}}" if hostname_is_valid else None
    )
    if not isinstance(server, dict) or server.get("url_template") != expected_url:
        add(
            "server.url_template must exactly match "
            "https://<server.hostname>/probe/{run_id}"
        )
    try:
        ipaddress.IPv4Address(server.get("private_ipv4", ""))
    except (AttributeError, ipaddress.AddressValueError):
        add("server.private_ipv4 must be the controlled endpoint IPv4")

    if config.get("private_relay_states") != ["off_control", "on"]:
        add("private_relay_states must contain off_control and on")
    if config.get("location_settings") != [
        "maintain_general_location",
        "country_and_time_zone",
    ]:
        add("location_settings must contain both declared Apple settings")
    if config.get("ingress_groups") != ["unpinned", "akamai", "apple_as714"]:
        add("ingress_groups must contain unpinned, akamai, and apple_as714")

    required_acceptance = {
        "exactly_one_attributable_server_connection",
        "fresh_tcp_syn_or_qualifying_quic_initial",
        "server_source_in_same_day_apple_egress_feed",
        "actual_ingress_observed_in_mac_pcap",
        "pinned_run_contacted_intended_ingress",
        "complete_client_server_and_utc_metadata",
        "unambiguous_one_to_one_pair",
    }
    acceptance = config.get("acceptance_rules")
    if (
        not isinstance(acceptance, list)
        or any(not isinstance(item, str) for item in acceptance)
        or set(acceptance) != required_acceptance
    ):
        add("acceptance_rules must preserve the full Step 9 measurement contract")
    required_exclusions = {
        "E01_NO_SERVER_OBSERVATION",
        "E02_MULTIPLE_SERVER_CONNECTIONS",
        "E03_NO_FRESH_FLOW",
        "E04_WRONG_OR_UNKNOWN_INGRESS",
        "E05_REAL_IP_AT_DESTINATION",
        "E06_EGRESS_NOT_IN_FEED",
        "E07_CLOCK_OR_LOG_CORRUPTION",
        "E08_CONDITION_CHANGED",
    }
    exclusions = config.get("exclusions")
    if not isinstance(exclusions, dict) or set(exclusions) != required_exclusions:
        add("exclusions must define exactly E01-E08")
    precedence = config.get("exclusion_precedence")
    if (
        not isinstance(precedence, list)
        or any(not isinstance(item, str) for item in (precedence or []))
        or len(precedence) != len(required_exclusions)
        or set(precedence) != required_exclusions
    ):
        add("exclusion_precedence must contain every E01-E08 code exactly once")

    objective = config.get("objective_3_ground_truth", {})
    required_objective = (
        "true_country_code",
        "true_time_zone",
        "maintain_general_location_boundary",
        "temporal_intersection_rule",
    )
    for key in required_objective:
        if not objective.get(key):
            add(f"objective_3_ground_truth.{key} is required")
    country_code = objective.get("true_country_code")
    if country_code and not re.fullmatch(r"[A-Z]{2}", str(country_code)):
        add("objective_3_ground_truth.true_country_code must be ISO alpha-2")
    permitted = objective.get("country_time_zone_permitted_apple_locations")
    if not permitted:
        add(
            "objective_3_ground_truth.country_time_zone_permitted_apple_locations is required"
        )
    elif not isinstance(permitted, list) or any(
        not isinstance(rule, dict)
        or not any(rule.get(field) for field in ("country", "region", "city"))
        for rule in permitted
    ):
        add(
            "objective_3_ground_truth.country_time_zone_permitted_apple_locations "
            "must contain explicit non-wildcard locations"
        )
    elif country_code and any(
        rule.get("country") and rule.get("country") != country_code
        for rule in permitted
    ):
        add(
            "objective_3_ground_truth.country_time_zone_permitted_apple_locations "
            "must remain within true_country_code"
        )
    boundary = objective.get("maintain_general_location_boundary")
    if boundary and (
        not isinstance(boundary, dict)
        or not boundary.get("boundary_id")
        or not boundary.get("allowed_country_codes")
        or not boundary.get("allowed_cities")
    ):
        add(
            "objective_3_ground_truth.maintain_general_location_boundary must "
            "declare an ID, allowed country codes, and primary allowed cities"
        )
    temporal_rule = objective.get("temporal_intersection_rule")
    supported_temporal_rules = {
        "exact_value_intersection",
        "exact_advertised_field_intersection",
    }
    temporal_fields = temporal_rule.get("fields") if isinstance(temporal_rule, dict) else None
    if temporal_rule and (
        not isinstance(temporal_rule, dict)
        or temporal_rule.get("rule_id") not in supported_temporal_rules
        or temporal_rule.get("comparison_normalization")
        != "trim_casefold_preserve_raw"
        or not isinstance(temporal_fields, list)
        or not temporal_fields
        or any(
            not isinstance(field, str)
            or field not in {"country", "region", "city"}
            for field in temporal_fields
        )
        or len(temporal_fields) != len(set(temporal_fields))
    ):
        add(
            "objective_3_ground_truth.temporal_intersection_rule must use a "
            "supported exact-intersection rule, trim_casefold_preserve_raw "
            "normalization, and unique country/region/city fields"
        )

    freshness = config.get("freshness", {})
    if not freshness.get("selected_method"):
        add("freshness.selected_method must be frozen after the pilot")
    elif freshness.get("selected_method") not in {"A", "B", "C", "D"}:
        add("freshness.selected_method must be A, B, C, or D")

    timeout = config.get("timeout_and_retry", {})
    browser_timeout = timeout.get("browser_response_timeout_seconds")
    operator_grace = timeout.get("operator_completion_grace_seconds")
    retries = timeout.get("maximum_attempts_per_scheduled_slot")
    if not isinstance(browser_timeout, int) or not 1 <= browser_timeout <= 600:
        add("timeout_and_retry.browser_response_timeout_seconds must be 1-600")
    if (
        not isinstance(operator_grace, int)
        or not isinstance(browser_timeout, int)
        or not browser_timeout < operator_grace <= 1800
    ):
        add(
            "timeout_and_retry.operator_completion_grace_seconds must exceed the "
            "browser response timeout and be at most 1800"
        )
    if not isinstance(retries, int) or not 1 <= retries <= 10:
        add("timeout_and_retry.maximum_attempts_per_scheduled_slot must be 1-10")
    if timeout.get("never_selectively_backfill_after_viewing_results") is not True:
        add("timeout_and_retry must forbid selective backfill")
    if timeout.get("retain_failed_aborted_and_timed_out_attempts") is not True:
        add("timeout_and_retry must retain every failed or timed-out attempt")

    capture = config.get("capture", {})
    snaplen = capture.get("client_snaplen_bytes")
    if not isinstance(snaplen, int) or not 96 <= snaplen <= 512:
        add("capture.client_snaplen_bytes must remain narrowly scoped (96-512)")
    if capture.get("promiscuous_mode") is not False:
        add("capture.promiscuous_mode must remain false")
    if capture.get("name_resolution") is not False:
        add("capture.name_resolution must remain false")
    if capture.get("recent_candidate_lookback_days") != 1:
        add("capture.recent_candidate_lookback_days must remain 1")
    if capture.get("recent_candidates_apply_to") != "pinned_and_unpinned_capture_only":
        add("capture recent candidates must apply to pinned and unpinned capture only")
    if (
        capture.get("pinned_acceptance_remains")
        != "intended_ingress_must_be_observed_in_the_attempt_capture"
    ):
        add("capture amendment must preserve packet-observed pin acceptance")
    if capture.get("pinned_capture_scope") != "intended_ingress_only":
        add("capture pinned scope must contain only the intended ingress")
    if capture.get("ingress_attribution_policy") != "bounded_candidate_contact_v2":
        add(
            "capture.ingress_attribution_policy must be "
            "bounded_candidate_contact_v2"
        )
    if (
        capture.get("historical_missing_policy_default")
        != "bounded_candidate_contact_v2"
    ):
        add("capture historical attempts must use bounded candidate attribution")
    if capture.get("recursive_candidate_inheritance") is not False:
        add("capture must forbid recursive candidate inheritance")
    if (
        capture.get("ingress_attribution_window")
        != "safari_launch_through_selected_caddy_request"
    ):
        add("capture ingress attribution must end at the selected Caddy request")

    pinning = config.get("pinning", {})
    if pinning.get("hostnames") != ["mask.icloud.com", "mask-h2.icloud.com"]:
        add("pinning.hostnames must contain both Private Relay mask names")
    if pinning.get("cname_target") != "mask.apple-dns.net":
        add("pinning.cname_target must remain mask.apple-dns.net")
    if pinning.get("hosts_file") != "/etc/hosts":
        add("pinning.hosts_file must remain /etc/hosts")
    if pinning.get("restart_networkserviceproxy") is not True:
        add("pinning must restart networkserviceproxy after hosts changes")

    fallback = config.get("targeted_fallback", {})
    if fallback.get("pf_anchor") != "com.apple/icpr-step9":
        add("targeted_fallback.pf_anchor must remain com.apple/icpr-step9")
    if fallback.get("measurement_server_udp_443_must_remain_available") is not True:
        add("targeted fallback must leave UDP/443 to the server available")
    if fallback.get("load_rule_before_dns_pin_restart") is not True:
        add("targeted fallback must load PF before restarting the pinned relay path")
    if fallback.get("reset_only_states_to_confirmed_ingress") is not True:
        add("targeted fallback must reset only states to the confirmed ingress")
    if fallback.get("require_positive_pf_block_counter") is not True:
        add("targeted fallback must require a positive PF block counter")
    if fallback.get("require_client_tcp_443_to_pinned_ingress") is not True:
        add("targeted fallback must require TCP/443 to the pinned ingress")
    if fallback.get("mask_h2_dns_query_is_supporting_not_required") is not True:
        add("targeted fallback must treat mask-h2 DNS as supporting evidence")

    schedule = config.get("daily_schedule", {})
    required_unpinned = [
        {"location": "maintain_general_location", "fresh_accepted_target": 2},
        {"location": "country_and_time_zone", "fresh_accepted_target": 2},
    ]
    if schedule.get("session_duration_minutes") != 45:
        add("daily_schedule.session_duration_minutes must remain 45")
    if schedule.get("unpinned_before_pinned") is not True:
        add("daily_schedule.unpinned_before_pinned must remain true")
    if schedule.get("unpinned_sequence") != required_unpinned:
        add("daily_schedule.unpinned_sequence must contain the two two-observation blocks")
    if not schedule.get("alternation_anchor_date_utc"):
        add("daily_schedule.alternation_anchor_date_utc must be predeclared")
    else:
        try:
            dt.date.fromisoformat(str(schedule["alternation_anchor_date_utc"]))
        except ValueError:
            add("daily_schedule.alternation_anchor_date_utc must be YYYY-MM-DD")
    if schedule.get("target_accepted_per_pinned_block") is None:
        add("daily_schedule.target_accepted_per_pinned_block must be frozen after the pilot")
    elif not isinstance(schedule.get("target_accepted_per_pinned_block"), int) or schedule[
        "target_accepted_per_pinned_block"
    ] < 1:
        add("daily_schedule.target_accepted_per_pinned_block must be a positive integer")
    expected_blocks = {
        "A": {"ingress_group": "akamai", "location": "maintain_general_location"},
        "B": {"ingress_group": "apple_as714", "location": "maintain_general_location"},
        "C": {"ingress_group": "akamai", "location": "country_and_time_zone"},
        "D": {"ingress_group": "apple_as714", "location": "country_and_time_zone"},
    }
    if schedule.get("pinned_blocks") != expected_blocks:
        add("daily_schedule.pinned_blocks must preserve balanced A-D conditions")
    for session in ("morning", "daytime", "evening"):
        for parity in ("odd", "even"):
            order = schedule.get(session, {}).get(f"pinned_order_on_{parity}_days", [])
            if not isinstance(order, list) or len(order) != 4 or set(order) != set(
                expected_blocks
            ):
                add(f"daily_schedule.{session} {parity}-day order must contain A-D once")
    if schedule.get("separate_unpinned_and_pinned_outputs") is not True:
        add("daily_schedule must keep unpinned and pinned outputs separate")
    if schedule.get("selective_backfill_forbidden") is not True:
        add("daily_schedule must forbid selective backfill")

    mapping = config.get("mapping", {})
    if not mapping.get("origin_asn_dataset_version"):
        add("mapping.origin_asn_dataset_version is required")
    if not mapping.get("akamai_sibling_asns"):
        add("mapping.akamai_sibling_asns must be reviewed and frozen")
    else:
        siblings = mapping["akamai_sibling_asns"]
        if not isinstance(siblings, list) or any(
            not isinstance(asn, int) or asn <= 0 or asn == 714 for asn in siblings
        ) or len(siblings) != len(set(siblings)):
            add("mapping.akamai_sibling_asns must be unique positive ASNs excluding 714")
    if mapping.get("apple_mapping_method") != "longest_prefix_match":
        add("mapping.apple_mapping_method must be longest_prefix_match")
    if mapping.get("third_party_geoip_is_primary") is not False:
        add("mapping.third_party_geoip_is_primary must remain false")
    if mapping.get("same_operator_rule") != "ingress_and_egress_operator_id_equal":
        add("mapping.same_operator_rule must compare infrastructure operator IDs")

    if config.get("configuration_status") != "frozen":
        add("configuration_status must be frozen")
    return gaps


def longest_prefix_match(address: str, rows: Iterable[dict[str, str]], field: str = "ip_prefix") -> dict[str, str] | None:
    ip = ipaddress.ip_address(address)
    best: tuple[int, dict[str, str]] | None = None
    for row in rows:
        prefix_text = row.get(field) or row.get("prefix")
        if not prefix_text:
            continue
        try:
            network = ipaddress.ip_network(prefix_text, strict=False)
        except ValueError:
            continue
        if ip.version == network.version and ip in network:
            candidate = (network.prefixlen, row)
            if best is None or candidate[0] > best[0]:
                best = candidate
    return best[1] if best else None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            normalized = {
                key: json.dumps(value, sort_keys=True, separators=(",", ":"))
                if isinstance(value, (dict, list))
                else value
                for key, value in row.items()
            }
            writer.writerow(normalized)
    os.replace(temporary, path)
