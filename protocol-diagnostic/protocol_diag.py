#!/usr/bin/env python3
"""Isolated ten-slot iCloud Private Relay protocol diagnostic controller."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
EXPERIMENT_ROOT = REPO_ROOT / "experiment"
sys.path.insert(0, str(EXPERIMENT_ROOT))

from icprlib import (  # noqa: E402
    IcprError,
    append_jsonl,
    finalize_attempt,
    parse_utc,
    sha256_file,
    software_snapshot,
    utc_now,
    verify_attempt,
    verify_sidecar,
    write_json,
    write_sidecar,
)

from platform_ops import (  # noqa: E402
    active_interface,
    apply_dns_pin,
    capture_filter,
    cleanup_attempt,
    hosts_target_entries,
    ipv6_default_route_status,
    prepare_firewall,
    process_command,
    process_running,
    render_pf_rule,
    start_capture,
    sudo_ready,
    sudo_run,
    system_validate_pf_rule,
    validate_rendered_pf_rule,
)
from pairing import (  # noqa: E402
    PairingError,
    exact_caddy_pair,
    server_flow_evidence,
    tshark_packets,
)
from series_profile import (  # noqa: E402
    SeriesProfile,
    get_profile_for_analysis_family,
    get_series_profile,
    series_profile_names,
)

DEFAULT_CONFIG = ROOT / "examples" / "dual-protocol-config.json"
DEFAULT_PLAN = ROOT / "examples" / "dual-protocol-plan.json"
CLIENT_ROOT = ROOT / "client"
REFERENCE_ROOT = ROOT / "reference"
RUNTIME_ROOT = ROOT / "runtime"
ACTIVE_SERIES_PROFILE = "dual_protocol"

LIVE_APPROVAL = "OPEN_ONE_DIAGNOSTIC_SAFARI_URL"
DNS_APPROVAL = "APPLY_DIAGNOSTIC_DNS_PIN"
FIREWALL_APPROVAL = "APPLY_DIAGNOSTIC_UDP_BLOCK"
DISRUPTIVE_APPROVAL = "ALTER_PRIVATE_RELAY_PROCESS_STATE"
DNS_QUERY_APPROVAL = "COLLECT_DIAGNOSTIC_DNS_CANDIDATES"
SERVER_SNAPSHOT_APPROVAL = "READ_ACTIVE_CADDY_PREFIX"
GATE_VALIDATE_APPROVAL = "VALIDATE_H3_REQUIRED_ORIGIN_GATE"
GATE_ARM_APPROVAL = "APPLY_TEMPORARY_H3_REQUIRED_ORIGIN_GATE"
GATE_DISARM_APPROVAL = "REMOVE_TEMPORARY_H3_REQUIRED_ORIGIN_GATE"

SCIENTIFIC_OUTCOMES = {
    "success",
    "timeout",
    "private_relay_unavailable",
    "alternative_ingress",
    "direct_bypass",
    "multiple_destination_connections",
    "aborted",
    "operator_completion_timeout",
}

SAFETY_STOP_CODES = {
    "CLOCK_OR_EVIDENCE_INTEGRITY_UNRELIABLE",
    "DNS_PIN_OR_RESTORATION_UNRELIABLE",
    "EFFECTIVE_PIN_UNVERIFIED",
    "HOSTS_OR_PF_RESTORATION_UNRELIABLE",
    "IPV6_BYPASS_NOT_EXCLUDED",
    "PF_RULE_SCOPE_OR_STATE_UNRELIABLE",
    "SERVER_EVIDENCE_UNAVAILABLE",
    "UNEXPECTED_SYSTEM_WIDE_NETWORK_EFFECT",
}


def fail(message: str) -> None:
    raise IcprError(message)


def activate_series_profile(profile: SeriesProfile) -> None:
    global DEFAULT_CONFIG, DEFAULT_PLAN, CLIENT_ROOT, REFERENCE_ROOT, RUNTIME_ROOT
    global ACTIVE_SERIES_PROFILE

    controlled_paths = (
        profile.config_path,
        profile.plan_path,
        profile.client_root,
        profile.derived_root,
        profile.reports_root,
        profile.runtime_root,
        profile.reference_root,
    )
    for path in controlled_paths:
        try:
            path.resolve().relative_to(ROOT.resolve())
        except ValueError:
            fail(f"series profile path is outside protocol-diagnostic: {path}")
    DEFAULT_CONFIG = profile.config_path
    DEFAULT_PLAN = profile.plan_path
    CLIENT_ROOT = profile.client_root
    REFERENCE_ROOT = profile.reference_root
    RUNTIME_ROOT = profile.runtime_root
    ACTIVE_SERIES_PROFILE = profile.name


def load_hash_verified_json(path: Path) -> tuple[dict[str, Any], str]:
    digest = verify_sidecar(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to read {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value, digest


def configured_server_private_ipv4(config: dict[str, Any]) -> str:
    from h3_gate import GateError, canonical_rfc1918_ipv4

    server = config.get("server")
    if not isinstance(server, dict):
        fail("diagnostic configuration lacks server settings")
    value = server.get("private_ipv4")
    try:
        canonical = canonical_rfc1918_ipv4(value)
    except GateError as exc:
        raise IcprError(f"configuration server.private_ipv4 is invalid: {exc}") from exc
    if value != canonical:
        fail("configuration server.private_ipv4 must be canonical")
    return canonical


def origin_gate_policy(config: dict[str, Any]) -> Any:
    from h3_gate import GateError, GatePolicy, canonical_rfc1918_ipv4

    origin_gate = config.get("origin_gate")
    if not isinstance(origin_gate, dict):
        fail("origin-gated configuration lacks origin_gate settings")
    value = origin_gate.get("private_ipv4")
    try:
        gate_private_ipv4 = canonical_rfc1918_ipv4(value)
    except GateError as exc:
        raise IcprError(
            f"configuration origin_gate.private_ipv4 is invalid: {exc}"
        ) from exc
    if value != gate_private_ipv4:
        fail("configuration origin_gate.private_ipv4 must be canonical")
    server_private_ipv4 = configured_server_private_ipv4(config)
    if gate_private_ipv4 != server_private_ipv4:
        fail("configuration origin_gate.private_ipv4 must equal server.private_ipv4")
    return GatePolicy(private_ipv4=server_private_ipv4)


def load_configuration(path: Path) -> tuple[dict[str, Any], str]:
    config, digest = load_hash_verified_json(path)
    if config.get("document_type") != "icpr_protocol_diagnostic_configuration":
        fail("diagnostic configuration has the wrong document type")
    if config.get("status") != "frozen" or config.get("schema_version") != 1:
        fail("diagnostic configuration is not frozen schema version 1")
    if config.get("campaign_isolation", {}).get("campaign_outputs_must_not_be_modified") is not True:
        fail("diagnostic configuration does not preserve campaign-output isolation")
    configured_server_private_ipv4(config)
    if config.get("analysis_family") in {"h3_required", "h3_response_probe"} or (
        "origin_gate" in config
    ):
        origin_gate_policy(config)
    references = (
        (
            config.get("fixed_conditions", {}).get("ingress_routing_evidence_path"),
            config.get("fixed_conditions", {}).get("ingress_routing_evidence_sha256"),
            "frozen ingress routing evidence",
        ),
        (
            config.get("dns", {}).get("recent_candidate_snapshot_path"),
            config.get("dns", {}).get("recent_candidate_snapshot_sha256"),
            "recent candidate snapshot",
        ),
    )
    for path_text, expected_hash, label in references:
        if not isinstance(path_text, str) or not re.fullmatch(
            r"[0-9a-f]{64}", str(expected_hash or "")
        ):
            fail(f"configuration lacks hash-pinned {label}")
        reference = REPO_ROOT / path_text
        actual = verify_sidecar(reference)
        if actual != expected_hash:
            fail(f"configuration hash mismatch for {label}: {reference}")
    return config, digest


def load_attempt_configuration(metadata: dict[str, Any]) -> dict[str, Any]:
    path_text = metadata.get("config_path")
    if not isinstance(path_text, str) or not path_text or Path(path_text).is_absolute():
        fail("attempt metadata lacks a repository-relative configuration path")
    config_path = (REPO_ROOT / path_text).resolve()
    try:
        config_path.relative_to(REPO_ROOT.resolve())
    except ValueError:
        fail("attempt configuration path is outside the repository")
    config, digest = load_configuration(config_path)
    if digest != metadata.get("config_sha256"):
        fail("attempt configuration hash differs from metadata")
    return config


def load_plan(
    path: Path, config_hash: str, *, series_profile: str | None = None
) -> tuple[dict[str, Any], str]:
    plan, digest = load_hash_verified_json(path)
    if plan.get("document_type") != "icpr_protocol_diagnostic_plan":
        fail("diagnostic plan has the wrong document type")
    if plan.get("status") != "frozen" or plan.get("schema_version") != 1:
        fail("diagnostic plan is not frozen schema version 1")
    if plan.get("configuration_sha256") != config_hash:
        fail("diagnostic plan configuration hash does not match")
    plan_version = str(plan.get("plan_version", ""))
    if not re.fullmatch(r"v[0-9]+", plan_version):
        fail("diagnostic plan version is invalid")
    try:
        profile = get_series_profile(series_profile or ACTIVE_SERIES_PROFILE)
    except ValueError as exc:
        fail(str(exc))
    slots = plan.get("slots")
    if not isinstance(slots, list) or len(slots) != len(profile.slot_conditions):
        fail(f"{profile.name} plan must contain exactly {len(profile.slot_conditions)} slots")
    if plan.get("analysis_family", "dual_protocol") != profile.analysis_family:
        fail("diagnostic plan has the wrong analysis family")
    if plan.get("denominator_id") != profile.denominator_id:
        fail("diagnostic plan has the wrong denominator")
    if profile.name == "h3_required":
        if plan.get("required_destination_protocol") != "HTTP/3.0":
            fail("H3-required plan does not require destination HTTP/3")
    if profile.name == "h3_response_probe":
        if plan.get("disposition") != "non_counted_exploratory":
            fail("H3 response probe is not marked non-counted exploratory")
        if plan.get("required_destination_protocol") != "HTTP/3.0":
            fail("H3 response probe does not require destination HTTP/3")
        if plan.get("maximum_attempts_per_slot") != 1:
            fail("H3 response probe must allow exactly one attempt")
    for index, (slot, condition) in enumerate(
        zip(slots, profile.slot_conditions), start=1
    ):
        if not isinstance(slot, dict):
            fail(f"diagnostic slot {index} is not an object")
        if profile.name == "h3_response_probe" and (
            "pair_number" in slot or "pair_position" in slot
        ):
            fail("H3 response probe cannot contain paired-design metadata")
        if slot.get("sequence_number") != index or slot.get("condition") != condition:
            fail("diagnostic slot order differs from the frozen alternating design")
        if slot.get("slot_id") != f"{profile.slot_prefix}-{plan_version}-{index:03d}":
            fail("diagnostic slot identifier differs from the frozen plan")
        if profile.name == "h3_required":
            expected_pair_position = "permitted" if index % 2 else "blocked"
            if (
                slot.get("pair_number") != (index + 1) // 2
                or slot.get("pair_position") != expected_pair_position
            ):
                fail("H3-required slot differs from the frozen paired design")
    return plan, digest


def generate_run_id() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = get_series_profile(ACTIVE_SERIES_PROFILE).run_prefix
    return f"{prefix}-{stamp}-{secrets.token_hex(8)}"


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _repo_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        fail(f"artifact is outside the repository: {path}")


def _write_immutable_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        fail(f"immutable artifact already exists: {path}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o440)
        os.link(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _parse_remote_caddy_stat(raw: bytes) -> dict[str, Any]:
    try:
        fields = raw.decode("utf-8").strip().split("\t")
    except UnicodeDecodeError as exc:
        fail(f"remote Caddy stat output is not UTF-8: {exc}")
    if len(fields) != 5:
        fail("remote Caddy stat output has the wrong field count")
    try:
        device, inode, size, mtime = (int(value) for value in fields[:4])
    except ValueError:
        fail("remote Caddy stat output contains a non-integer field")
    if min(device, inode, size, mtime) < 0 or fields[4] != "regular file":
        fail("remote Caddy source is not a valid regular file")
    return {
        "device": device,
        "inode": inode,
        "size_bytes": size,
        "mtime_unix": mtime,
        "file_type": fields[4],
    }


def _validate_caddy_prefix_content(
    content: bytes, required_run_ids: list[str], purpose: str
) -> tuple[int, dict[str, int]]:
    if not content or not content.endswith(b"\n"):
        fail("active Caddy snapshot is empty or ends with an incomplete JSONL row")
    counts = {run_id: 0 for run_id in required_run_ids}
    row_count = 0
    for number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"active Caddy snapshot contains invalid JSON at line {number}: {exc}")
        if not isinstance(row, dict):
            fail(f"active Caddy snapshot row is not an object at line {number}")
        row_count += 1
        run_id = str(row.get("run_id", ""))
        if run_id in counts:
            counts[run_id] += 1
    if purpose == "readiness":
        if len(required_run_ids) != 1 or counts.get(required_run_ids[0]) != 1:
            fail("readiness run ID must occur exactly once in the complete Caddy prefix")
    elif purpose == "diagnostic_final":
        missing = [run_id for run_id, count in counts.items() if count == 0]
        if missing:
            fail("final Caddy prefix lacks diagnostic run IDs: " + ", ".join(missing))
    else:
        fail(f"unsupported active Caddy snapshot purpose: {purpose}")
    return row_count, counts


def verify_caddy_snapshot_provenance(
    provenance_path: Path, caddy_path: Path, caddy_hash: str
) -> dict[str, Any]:
    provenance, _ = load_hash_verified_json(provenance_path)
    if (
        provenance.get("schema_version") != 1
        or provenance.get("document_type") != "icpr_live_caddy_prefix_snapshot"
        or provenance.get("status") != "verified"
    ):
        fail("Caddy snapshot provenance has the wrong schema, type, or status")
    if (
        provenance.get("capture_method") != "nonselective_active_log_byte_prefix_v1"
        or provenance.get("source_nonselective_prefix") is not True
        or provenance.get("source_mutated") is not False
    ):
        fail("Caddy snapshot provenance does not establish a non-selective read-only prefix")
    if provenance.get("snapshot_path") != _repo_relative(caddy_path):
        fail("Caddy snapshot provenance names a different artifact")
    if provenance.get("snapshot_sha256") != caddy_hash:
        fail("Caddy snapshot provenance hash differs from the artifact")
    if provenance.get("prefix_bytes") != caddy_path.stat().st_size:
        fail("Caddy snapshot provenance byte count differs from the artifact")
    before = provenance.get("source_stat_before")
    after = provenance.get("source_stat_after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        fail("Caddy snapshot provenance lacks source stat records")
    if before.get("device") != after.get("device") or before.get("inode") != after.get("inode"):
        fail("Caddy snapshot source changed identity during capture")
    if not (
        int(before.get("size_bytes", -1))
        <= int(provenance.get("prefix_bytes", -1))
        <= int(after.get("size_bytes", -1))
    ):
        fail("Caddy snapshot byte prefix is inconsistent with source stat records")
    return provenance


def attempt_directories() -> list[Path]:
    return sorted(path.parent for path in CLIENT_ROOT.rglob("metadata.json"))


def attempt_metadata(path: Path) -> dict[str, Any]:
    try:
        value = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"diagnostic attempt metadata is unreadable: {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"diagnostic attempt metadata is not an object: {path}")
    return value


def find_attempt(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_dir():
        resolved = candidate.resolve()
    else:
        matches = [path for path in attempt_directories() if path.name == value]
        if len(matches) != 1:
            fail(f"could not resolve exactly one diagnostic attempt for {value!r}")
        resolved = matches[0].resolve()
    try:
        resolved.relative_to(CLIENT_ROOT.resolve())
    except ValueError:
        fail("attempt path is outside the isolated protocol-diagnostic client root")
    if not (resolved / "metadata.json").is_file():
        fail("diagnostic attempt metadata is absent")
    return resolved


def read_finished_event(path: Path) -> dict[str, Any] | None:
    events_path = path / "events.jsonl"
    if not events_path.is_file():
        return None
    events = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "run_finished":
            events.append(event)
    if len(events) > 1:
        fail(f"diagnostic attempt has multiple run_finished events: {path}")
    return events[0] if events else None


def prior_attempt_state(plan: dict[str, Any], plan_hash: str) -> dict[str, list[tuple[Path, dict[str, Any], dict[str, Any]]]]:
    grouped: dict[str, list[tuple[Path, dict[str, Any], dict[str, Any]]]] = {
        str(slot["slot_id"]): [] for slot in plan["slots"]
    }
    for path in attempt_directories():
        metadata = attempt_metadata(path)
        if metadata.get("diagnostic_id") != plan.get("diagnostic_id"):
            continue
        if metadata.get("plan_sha256") != plan_hash:
            fail(f"diagnostic contains an attempt from a different plan: {path}")
        slot_id = str(metadata.get("slot_id"))
        if slot_id not in grouped:
            fail(f"diagnostic attempt names a slot absent from the frozen plan: {path}")
        if not (path / "manifest.sha256").is_file():
            fail(f"unfinished diagnostic attempt requires finish/abort/cleanup: {path}")
        verify_attempt(path)
        finished = read_finished_event(path)
        if not finished:
            fail(f"finalized diagnostic attempt lacks run_finished: {path}")
        grouped[slot_id].append((path, metadata, finished))
    for attempts in grouped.values():
        attempts.sort(key=lambda item: int(item[1].get("retry_number", 0)))
    return grouped


def slot_complete(
    attempts: list[tuple[Path, dict[str, Any], dict[str, Any]]], maximum: int
) -> bool:
    if not attempts:
        return False
    for _, _, event in attempts:
        if event.get("outcome") in SCIENTIFIC_OUTCOMES:
            return True
        if (
            event.get("outcome") in {"mechanical_failure", "prepare_error"}
            and event.get("retry_authorized") is not True
        ):
            # The frozen retry policy does not allow another attempt. Retain the
            # failed slot as planned-but-invalid and continue in sequence.
            return True
    return any(
        int(metadata.get("retry_number", 0)) == maximum
        and event.get("outcome") in {"mechanical_failure", "prepare_error"}
        for _, metadata, event in attempts
    )


def safety_stop_reasons(
    grouped: dict[str, list[tuple[Path, dict[str, Any], dict[str, Any]]]]
) -> list[str]:
    reasons: list[str] = []
    for attempts in grouped.values():
        for path, metadata, event in attempts:
            response_bypass = False
            response_path = path / "response.json"
            if response_path.is_file():
                try:
                    response = json.loads(response_path.read_text(encoding="utf-8"))
                    response_bypass = bool(
                        response.get("remote_ip")
                        and response.get("remote_ip") == metadata.get("real_public_ipv4")
                    )
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    reasons.append(
                        f"response-evidence integrity safety stop remains latched: {path}: {exc}"
                    )
            if event.get("outcome") == "direct_bypass" or response_bypass:
                reasons.append(f"real-client-IP bypass safety stop remains latched: {path}")
            if event.get("condition_changed") is True:
                reasons.append(f"condition-change safety stop remains latched: {path}")
            if event.get("safety_stop_code"):
                reasons.append(
                    f"{event['safety_stop_code']} safety stop remains latched: {path}"
                )
    return reasons


def validate_slot_request(
    plan: dict[str, Any],
    plan_hash: str,
    *,
    slot_id: str,
    retry_number: int,
    condition: str,
) -> None:
    maximum = int(plan["maximum_attempts_per_slot"])
    if retry_number < 1 or retry_number > maximum:
        fail(f"retry number must be between 1 and {maximum}")
    matches = [slot for slot in plan["slots"] if slot["slot_id"] == slot_id]
    if len(matches) != 1 or matches[0]["condition"] != condition:
        fail("requested slot or condition differs from the frozen plan")
    grouped = prior_attempt_state(plan, plan_hash)
    current = grouped[slot_id]
    if any(int(metadata.get("retry_number", 0)) == retry_number for _, metadata, _ in current):
        fail("diagnostic slot/retry already exists and will not be overwritten")
    if retry_number == 1 and current:
        fail("first attempt requested for a slot that already has an attempt")
    if retry_number > 1:
        previous = [item for item in current if int(item[1].get("retry_number", 0)) == retry_number - 1]
        if len(previous) != 1:
            fail("retry requires exactly one immediately preceding finalized attempt")
        prior_event = previous[0][2]
        if prior_event.get("outcome") not in {"mechanical_failure", "prepare_error"}:
            fail("retry is forbidden after a scientific network outcome")
        if prior_event.get("retry_authorized") is not True:
            fail("prior mechanical failure does not authorize a retry")
    slot_index = next(index for index, slot in enumerate(plan["slots"]) if slot["slot_id"] == slot_id)
    for earlier in plan["slots"][:slot_index]:
        if not slot_complete(grouped[str(earlier["slot_id"])], maximum):
            fail(f"earlier diagnostic slot is incomplete: {earlier['slot_id']}")
    for later in plan["slots"][slot_index + 1 :]:
        if grouped[str(later["slot_id"])]:
            fail("selective backfill is forbidden after a later diagnostic slot")


def verify_campaign_completion(config: dict[str, Any]) -> dict[str, Any]:
    gate = config["campaign_completion_gate"]
    attestation_path = REPO_ROOT / str(gate["attestation_path"])
    report: dict[str, Any] = {
        "ready": False,
        "attestation_path": str(attestation_path),
        "blockers": [],
    }
    if dt.datetime.now(dt.timezone.utc) < parse_utc(str(gate["diagnostic_not_before_utc"])):
        report["blockers"].append(
            f"diagnostic is frozen not to start before {gate['diagnostic_not_before_utc']}"
        )
    if not attestation_path.is_file():
        report["blockers"].append("post-campaign completion attestation is absent")
        return report
    try:
        attestation, digest = load_hash_verified_json(attestation_path)
    except IcprError as exc:
        report["blockers"].append(str(exc))
        return report
    report["attestation_sha256"] = digest

    def attested_integer(field: str, default: int) -> int:
        try:
            return int(attestation.get(field, default))
        except (TypeError, ValueError):
            report["blockers"].append(f"attestation field {field} is not an integer")
            return default

    completed_days = attested_integer("completed_campaign_days", 0)
    pending_count = attested_integer("final_pending_mappings", -1)
    dated_gap_count = attested_integer("final_dated_asn_gaps", -1)
    if (
        attestation.get("schema_version") != 1
        or attestation.get("document_type")
        != "icpr_protocol_diagnostic_campaign_completion_attestation"
    ):
        report["blockers"].append(
            "campaign completion attestation has the wrong schema or document type"
        )
    if attestation.get("status") != "verified":
        report["blockers"].append("campaign completion attestation is not verified")
    if completed_days < int(gate["minimum_completed_campaign_days"]):
        report["blockers"].append("fewer than fourteen campaign days are attested")
    if attestation.get("campaign_end_date_utc") != gate["campaign_end_date_utc"]:
        report["blockers"].append("attested campaign end date differs from the frozen gate")
    if attestation.get("backup_verified") is not True:
        report["blockers"].append("post-campaign archive backup is not attested as verified")
    if pending_count != 0:
        report["blockers"].append("final campaign pairing does not attest zero pending mappings")
    if dated_gap_count != 0:
        report["blockers"].append("final campaign pairing does not attest zero dated-ASN gaps")
    if attestation.get("final_pairing_command") != (
        "./experiment/icpr pair --server-root server/recovery-data"
    ):
        report["blockers"].append("attested final pairing command is not the required command")
    references = (
        ("post_campaign_pull_path", "post_campaign_pull_sha256"),
        ("final_pairs_path", "final_pairs_sha256"),
        ("dated_asn_gap_report_path", "dated_asn_gap_report_sha256"),
    )
    for path_field, hash_field in references:
        path_text = attestation.get(path_field)
        if not isinstance(path_text, str):
            report["blockers"].append(f"attestation lacks {path_field}")
            continue
        path = REPO_ROOT / path_text
        if not path.is_file():
            report["blockers"].append(f"attested file is absent: {path}")
        elif sha256_file(path) != attestation.get(hash_field):
            report["blockers"].append(f"attested hash mismatch: {path}")
    pairs_path_text = attestation.get("final_pairs_path")
    if isinstance(pairs_path_text, str):
        pairs_path = REPO_ROOT / pairs_path_text
        if pairs_path.is_file():
            try:
                with pairs_path.open("r", encoding="utf-8", newline="") as handle:
                    rows = list(csv.DictReader(handle))
                if not rows or "pending_reason" not in rows[0] or "disposition" not in rows[0]:
                    fail("final pairs CSV lacks pending/disposition fields")
                pending_rows = [
                    row
                    for row in rows
                    if row.get("disposition") == "pending" or bool(row.get("pending_reason"))
                ]
                dated_asn_gaps = [
                    row
                    for row in rows
                    if row.get("pending_reason") == "dated_asn_mapping_missing"
                ]
                report["final_pairs_pending_count"] = len(pending_rows)
                report["final_pairs_dated_asn_gap_count"] = len(dated_asn_gaps)
                if len(pending_rows) != pending_count:
                    report["blockers"].append(
                        "attested pending count differs from the hash-verified final pairs CSV"
                    )
                if pending_rows:
                    report["blockers"].append(
                        "hash-verified final pairs CSV still contains pending mappings"
                    )
                if len(dated_asn_gaps) != dated_gap_count:
                    report["blockers"].append(
                        "attested dated-ASN gap count differs from the final pairs CSV"
                    )
                if dated_asn_gaps:
                    report["blockers"].append(
                        "hash-verified final pairs CSV still contains dated-ASN gaps"
                    )
            except (OSError, UnicodeError, csv.Error, ValueError, IcprError) as exc:
                report["blockers"].append(f"unable to verify final pairing/gap counts: {exc}")
    last_campaign_attempt = attestation.get("last_campaign_attempt_utc")
    post_pull = attestation.get("post_campaign_pull_utc")
    try:
        if parse_utc(str(post_pull)) <= parse_utc(str(last_campaign_attempt)):
            report["blockers"].append("post-campaign archive pull is not later than the last attempt")
    except IcprError:
        report["blockers"].append("attested campaign/pull timestamps are invalid")
    report["ready"] = not report["blockers"]
    if isinstance(attestation.get("last_campaign_attempt_utc"), str):
        report["attested_last_campaign_attempt_utc"] = attestation[
            "last_campaign_attempt_utc"
        ]
    return report


def campaign_attempt_blockers(completion: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    attested_text = completion.get("attested_last_campaign_attempt_utc")
    attested = None
    if isinstance(attested_text, str):
        try:
            attested = parse_utc(attested_text)
        except IcprError as exc:
            blockers.append(f"attested last campaign attempt timestamp is invalid: {exc}")
    for metadata_path in sorted((EXPERIMENT_ROOT / "client").rglob("metadata.json")):
        attempt_dir = metadata_path.parent
        if not (attempt_dir / "manifest.sha256").is_file():
            blockers.append(f"normal campaign attempt is not hash-finalized: {attempt_dir}")
            continue
        if attested is None:
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            started = parse_utc(
                str(
                    metadata.get("client_start_utc")
                    or metadata.get("safari_launch_utc")
                    or metadata.get("started_utc")
                )
            )
        except (OSError, UnicodeError, json.JSONDecodeError, IcprError) as exc:
            blockers.append(f"normal campaign attempt metadata is unreadable: {attempt_dir}: {exc}")
            continue
        if started > attested:
            blockers.append(
                f"normal campaign attempt postdates the completion attestation: {attempt_dir}"
            )
    return blockers


def verify_run_day_readiness(config: dict[str, Any]) -> dict[str, Any]:
    path = REPO_ROOT / str(config["server"]["run_day_readiness_attestation_path"])
    report: dict[str, Any] = {"ready": False, "path": str(path), "blockers": []}
    if not path.is_file():
        report["blockers"].append("run-day HTTP/3/UDP readiness attestation is absent")
        return report
    try:
        attestation, digest = load_hash_verified_json(path)
        report["sha256"] = digest
        if (
            attestation.get("schema_version") != 1
            or attestation.get("document_type")
            != "icpr_protocol_diagnostic_run_day_http3_readiness"
        ):
            fail("readiness attestation has the wrong schema or document type")
        if attestation.get("status") != "verified" or attestation.get("counted_observation") is not False:
            fail("readiness attestation is not verified and explicitly non-counted")
        completed_text = str(attestation.get("completed_utc"))
        completed = parse_utc(completed_text)
        started = parse_utc(str(attestation.get("started_utc")))
        today = dt.datetime.now(dt.timezone.utc).date()
        if started.date() != today or completed.date() != today:
            fail("HTTP/3/UDP readiness evidence is not from the current UTC execution day")
        if completed < started:
            fail("HTTP/3/UDP readiness completion precedes its start")
        age = (dt.datetime.now(dt.timezone.utc) - completed).total_seconds()
        if age < 0 or age > int(config["server"]["run_day_readiness_max_age_seconds"]):
            fail("HTTP/3/UDP readiness evidence is older than the frozen limit")
        references: dict[str, tuple[Path, str]] = {}
        for label in ("response", "caddy", "caddy_snapshot_provenance", "server_pcap"):
            artifact = REPO_ROOT / str(attestation.get(f"{label}_path", ""))
            expected = str(attestation.get(f"{label}_sha256", ""))
            if not artifact.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected):
                fail(f"readiness {label} artifact reference is absent or invalid")
            actual = verify_sidecar(artifact)
            if actual != expected:
                fail(f"readiness {label} artifact hash mismatch")
            references[label] = (artifact, actual)
        provenance = verify_caddy_snapshot_provenance(
            references["caddy_snapshot_provenance"][0],
            references["caddy"][0],
            references["caddy"][1],
        )
        if provenance.get("purpose") != "readiness":
            fail("run-day readiness cites a Caddy snapshot with the wrong purpose")
        if provenance.get("required_run_ids") != [attestation.get("run_id")]:
            fail("run-day readiness Caddy snapshot names a different required run ID")
        if provenance.get("matched_run_id_counts", {}).get(attestation.get("run_id")) != 1:
            fail("run-day readiness run ID is not unique in the complete Caddy prefix")
        snapshot_utc = parse_utc(str(provenance.get("captured_utc")))
        if snapshot_utc.date() != today or snapshot_utc < completed:
            fail("run-day readiness Caddy snapshot was not captured after the request on this UTC day")
        response = json.loads(references["response"][0].read_text(encoding="utf-8"))
        caddy_path = references["caddy"][0]
        opener = gzip.open if caddy_path.suffix == ".gz" else open
        rows: list[dict[str, Any]] = []
        with opener(caddy_path, "rt", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        metadata = {"run_id": attestation.get("run_id")}
        caddy_row, errors = exact_caddy_pair(rows, metadata, response)
        if caddy_row is None or errors:
            fail("run-day readiness Caddy/response pairing is not exact: " + "; ".join(errors))
        if response.get("http_protocol") != "HTTP/3.0":
            fail("run-day readiness response is not HTTP/3")
        request = caddy_row["request"]
        display = (
            f"ip.src=={request['remote_ip']} && ip.dst=={config['server']['private_ipv4']} "
            f"&& udp.srcport=={request['remote_port']} && udp.dstport==443"
        )
        packets = tshark_packets(
            references["server_pcap"][0],
            references["server_pcap"][1],
            display,
        )
        # The documented readiness command records UTC timestamps to whole
        # seconds. Treat its completion value as the inclusive end of that
        # recorded second when matching sub-second packet/Caddy timestamps.
        flow_end = completed
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", completed_text):
            flow_end += dt.timedelta(seconds=1) - dt.timedelta(microseconds=1)
        flow = server_flow_evidence(
            packets,
            caddy_row,
            str(config["server"]["private_ipv4"]),
            started,
            flow_end,
        )
        if not flow.get("fresh") or flow.get("transport") != "udp_quic_initial":
            fail("run-day readiness lacks a fresh exact server QUIC/UDP flow")
        report.update(
            {
                "ready": True,
                "run_id": attestation.get("run_id"),
                "completed_utc": attestation.get("completed_utc"),
                "http_protocol": response.get("http_protocol"),
                "server_flow": flow,
            }
        )
    except (
        IcprError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        PairingError,
    ) as exc:
        report["blockers"].append(str(exc))
    return report


def feed_for_day(day: str) -> tuple[Path, str]:
    path = EXPERIMENT_ROOT / "feeds" / "apple" / day / "apple-egress.csv"
    if not path.is_file():
        fail(f"same-day Apple egress feed is absent: {path}")
    return path, verify_sidecar(path)


def dated_pin_mapping(day: str, config: dict[str, Any]) -> tuple[Path, str, dict[str, str]]:
    path = EXPERIMENT_ROOT / "reference" / "asn" / "origin_prefixes.csv"
    digest = verify_sidecar(path)
    pin = ipaddress.IPv4Address(str(config["fixed_conditions"]["intended_ingress_ipv4"]))
    candidates: list[tuple[int, dict[str, str]]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("date") != day:
                continue
            try:
                network = ipaddress.ip_network(str(row.get("prefix")), strict=True)
            except ValueError:
                continue
            if pin in network and all(
                row.get(field) for field in ("prefix", "asn", "source", "source_hash")
            ):
                candidates.append((network.prefixlen, row))
    if not candidates:
        fail("same-day origin-ASN mapping for the fixed diagnostic pin is absent")
    longest = max(prefix for prefix, _ in candidates)
    rows = [row for prefix, row in candidates if prefix == longest]
    expected_asn = str(config["fixed_conditions"]["intended_ingress_asn"])
    if len(rows) != 1 or rows[0].get("asn") != expected_asn:
        fail("same-day fixed-pin origin-ASN mapping is absent or ambiguous")
    row = dict(rows[0])
    source_hash = str(row.get("source_hash", "")).lower()
    if not str(row.get("source", "")).startswith("RIPEstat ") or not re.fullmatch(
        r"[0-9a-f]{64}", source_hash
    ):
        fail("same-day fixed-pin mapping lacks bounded RIPEstat provenance")
    evidence_matches: list[Path] = []
    for evidence in sorted((EXPERIMENT_ROOT / "reference" / "asn").rglob("*.json")):
        sidecar = evidence.with_name(evidence.name + ".sha256")
        if not sidecar.is_file() or sha256_file(evidence) != source_hash:
            continue
        if verify_sidecar(evidence) == source_hash:
            evidence_matches.append(evidence)
    if not evidence_matches:
        fail("same-day fixed-pin mapping source_hash has no verified RIPE evidence file")
    row["source_evidence_path"] = str(evidence_matches[0].relative_to(REPO_ROOT))
    return path, digest, row


def parse_dig_answers(stdout: str) -> list[dict[str, Any]]:
    answers: list[dict[str, Any]] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        fields = line.split()
        if len(fields) < 5 or fields[2] != "IN":
            continue
        answers.append(
            {
                "name": fields[0].rstrip("."),
                "ttl": int(fields[1]),
                "type": fields[3],
                "value": fields[4].rstrip("."),
            }
        )
    return answers


def collect_dns_snapshot(config: dict[str, Any], *, purpose: str) -> dict[str, Any]:
    names = list(config["dns"]["snapshot_names"])
    responses: dict[str, Any] = {}
    candidate_hostname_map: dict[str, set[str]] = {}
    for name in names:
        responses[name] = {}
        for query_type in ("CNAME", "A", "AAAA"):
            result = subprocess.run(
                ["dig", name, query_type, "+noall", "+answer"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            answers = parse_dig_answers(result.stdout)
            responses[name][query_type] = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "answers": answers,
            }
            if query_type == "A":
                for answer in answers:
                    if answer["type"] != "A":
                        continue
                    try:
                        address = str(ipaddress.IPv4Address(answer["value"]))
                    except ValueError:
                        continue
                    candidate_hostname_map.setdefault(address, set()).add(name)
                    candidate_hostname_map[address].add(str(answer["name"]))
        effective = subprocess.run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        responses[name]["macos_effective"] = {
            "returncode": effective.returncode,
            "stdout": effective.stdout,
            "stderr": effective.stderr,
        }
        for match in re.finditer(r"^ip_address:\s*(\S+)\s*$", effective.stdout, re.MULTILINE):
            try:
                address = str(ipaddress.IPv4Address(match.group(1)))
            except ValueError:
                continue
            candidate_hostname_map.setdefault(address, set()).add(name)
    pin = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    origin = str(config["server"]["public_ipv4"])
    candidate_hostname_map.setdefault(pin, set()).update(config["dns"]["mask_hostnames"])
    candidate_hostname_map.setdefault(origin, set()).add(config["server"]["hostname"])
    observed_origin = {
        answer["value"]
        for answer in responses[config["server"]["hostname"]]["A"]["answers"]
        if answer["type"] == "A"
    }
    if observed_origin != {origin}:
        fail(
            f"controlled-origin DNS did not resolve exactly to frozen IPv4 {origin}: "
            f"{sorted(observed_origin)}"
        )
    recent_reference: dict[str, Any] | None = None
    recent_campaign_provenance: list[dict[str, Any]] = []
    extra_capture_candidates: set[str] = set()
    if purpose == "run_day":
        reference_path = REPO_ROOT / str(config["dns"]["recent_candidate_snapshot_path"])
        reference, reference_hash = load_hash_verified_json(reference_path)
        if reference_hash != config["dns"]["recent_candidate_snapshot_sha256"]:
            fail("recent candidate snapshot differs from the frozen configuration")
        reference_map = reference.get("candidate_hostname_map")
        if not isinstance(reference_map, dict):
            fail("recent candidate snapshot hostname map is invalid")
        for address, hostnames in reference_map.items():
            normalized = str(ipaddress.IPv4Address(address))
            if not isinstance(hostnames, list):
                fail("recent candidate snapshot contains invalid hostname provenance")
            candidate_hostname_map.setdefault(normalized, set()).update(
                str(hostname).rstrip(".").lower() for hostname in hostnames
            )
        recent_reference = {
            "path": str(reference_path.relative_to(REPO_ROOT)),
            "sha256": reference_hash,
            "recorded_utc": reference.get("recorded_utc"),
        }
        from controller import recent_capture_candidate_evidence

        # The normal campaign is frozen after its attested end. A diagnostic
        # delayed by several days must still include candidates directly seen
        # on the final bounded campaign days, while the resolver queries above
        # independently contribute current run-day candidates.
        day = str(config["campaign_completion_gate"]["campaign_end_date_utc"])
        recent_addresses, recent_campaign_provenance = recent_capture_candidate_evidence(
            day,
            lookback_days=int(config["dns"]["recent_campaign_candidate_lookback_days"]),
            client_root=EXPERIMENT_ROOT / "client",
        )
        extra_capture_candidates.update(recent_addresses)
        for item in recent_campaign_provenance:
            address = str(ipaddress.IPv4Address(item["address"]))
            for source in item.get("source_fields", []):
                match = re.fullmatch(r"effective_dns\.hostnames\.(.+)\.A", str(source))
                if match and match.group(1) in config["dns"]["mask_hostnames"]:
                    candidate_hostname_map.setdefault(address, set()).add(match.group(1))
    capture_candidates = sorted(
        set(candidate_hostname_map) | extra_capture_candidates,
        key=ipaddress.IPv4Address,
    )
    fallback = sorted(
        address
        for address, hostnames in candidate_hostname_map.items()
        if "mask-h2.icloud.com" in hostnames and address not in {pin, origin}
    )
    result = {
        "schema_version": 1,
        "document_type": "icpr_protocol_diagnostic_dns_candidate_snapshot",
        "purpose": purpose,
        "recorded_utc": utc_now(),
        "responses": responses,
        "fixed_ingress_ipv4": pin,
        "origin_public_ipv4": origin,
        "fallback_candidate_ipv4": fallback,
        "capture_candidates": capture_candidates,
        "candidate_hostname_map": {
            address: sorted(hostnames)
            for address, hostnames in sorted(
                candidate_hostname_map.items(), key=lambda item: ipaddress.IPv4Address(item[0])
            )
        },
        "absence_of_dns_query_is_not_absence_of_fallback": True,
    }
    if recent_reference is not None:
        result["recent_candidate_snapshot"] = recent_reference
        result["recent_campaign_candidate_anchor_date_utc"] = str(
            config["campaign_completion_gate"]["campaign_end_date_utc"]
        )
        result["recent_campaign_candidate_provenance"] = recent_campaign_provenance
    return result


def verify_candidate_snapshot(
    path: Path, config: dict[str, Any], *, require_run_day: bool
) -> tuple[dict[str, Any], str]:
    snapshot, digest = load_hash_verified_json(path)
    if snapshot.get("document_type") != "icpr_protocol_diagnostic_dns_candidate_snapshot":
        fail("candidate snapshot has the wrong document type")
    recorded = parse_utc(str(snapshot.get("recorded_utc")))
    now = dt.datetime.now(dt.timezone.utc)
    if require_run_day and recorded.date() != now.date():
        fail("candidate snapshot is not from the current UTC execution day")
    if require_run_day and snapshot.get("purpose") != "run_day":
        fail("candidate snapshot is not labelled as a run-day snapshot")
    pin = str(config["fixed_conditions"]["intended_ingress_ipv4"])
    origin = str(config["server"]["public_ipv4"])
    candidates = snapshot.get("capture_candidates")
    if not isinstance(candidates, list) or pin not in candidates or origin not in candidates:
        fail("candidate snapshot does not include both fixed ingress and controlled origin")
    normalized = [str(ipaddress.IPv4Address(value)) for value in candidates]
    if normalized != sorted(set(normalized), key=ipaddress.IPv4Address):
        fail("candidate snapshot IPv4 list is not unique and canonically sorted")
    mapping = snapshot.get("candidate_hostname_map")
    if not isinstance(mapping, dict) or not set(mapping).issubset(set(normalized)):
        fail("candidate snapshot hostname map is outside its IPv4 list")
    if not all(isinstance(hostnames, list) and hostnames for hostnames in mapping.values()):
        fail("candidate snapshot contains empty or invalid hostname provenance")
    fallback = snapshot.get("fallback_candidate_ipv4")
    if not isinstance(fallback, list) or not fallback:
        fail("candidate snapshot contains no mask-h2 fallback candidates")
    if not set(fallback).issubset(set(normalized)):
        fail("fallback candidates are outside the frozen capture candidate list")
    if require_run_day:
        responses = snapshot.get("responses")
        if not isinstance(responses, dict):
            fail("run-day candidate snapshot lacks DNS response evidence")
        for hostname in config["dns"]["mask_hostnames"]:
            a_response = responses.get(hostname, {}).get("A", {})
            answers = a_response.get("answers", []) if isinstance(a_response, dict) else []
            if a_response.get("returncode") != 0 or not any(
                answer.get("type") == "A" for answer in answers if isinstance(answer, dict)
            ):
                fail(f"run-day A lookup failed or returned no IPv4 candidates: {hostname}")
        recent = snapshot.get("recent_candidate_snapshot")
        if not isinstance(recent, dict):
            fail("run-day snapshot lacks the frozen recently-known candidate union")
        recent_path = REPO_ROOT / str(config["dns"]["recent_candidate_snapshot_path"])
        recent_snapshot, recent_hash = load_hash_verified_json(recent_path)
        if (
            recent.get("sha256") != recent_hash
            or recent_hash != config["dns"]["recent_candidate_snapshot_sha256"]
        ):
            fail("run-day snapshot references the wrong recently-known candidate set")
        if snapshot.get("recent_campaign_candidate_anchor_date_utc") != config[
            "campaign_completion_gate"
        ]["campaign_end_date_utc"]:
            fail("run-day snapshot uses the wrong bounded campaign-candidate anchor date")
        recent_candidates = set(recent_snapshot.get("capture_candidates", []))
        if not recent_candidates.issubset(set(normalized)):
            fail("run-day capture scope omits recently-known exact candidates")
    return snapshot, digest


def campaign_preflight(
    config: dict[str, Any], plan: dict[str, Any], plan_hash: str
) -> dict[str, Any]:
    dependencies = {
        name: bool(subprocess.run(["/usr/bin/which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
        for name in ("dig", "tcpdump", "tshark", "pfctl", "dscacheutil", "open", "shasum")
    }
    software = software_snapshot()
    expected_safari = str(config["fixed_conditions"]["safari_client"])
    if expected_safari.startswith("Safari "):
        expected_safari = expected_safari.removeprefix("Safari ")
    hosts_path = Path(str(config["pinning"]["hosts_file"]))
    try:
        hosts_content = hosts_path.read_bytes()
        pin_names = config["pinning"].get(
            "direct_hostnames", [str(config["pinning"]["cname_target"])]
        )
        hosts_entries = [
            entry
            for name in pin_names
            for entry in hosts_target_entries(hosts_content, str(name))
        ]
        hosts_clean = not hosts_entries
    except (OSError, UnicodeDecodeError) as exc:
        hosts_clean = False
        hosts_entries = [{"error": str(exc)}]
    unfinished = [
        str(path)
        for path in attempt_directories()
        if not (path / "manifest.sha256").is_file()
    ]
    grouped: dict[str, list[tuple[Path, dict[str, Any], dict[str, Any]]]] | None = None
    try:
        grouped = prior_attempt_state(plan, plan_hash)
    except IcprError as exc:
        unfinished.append(str(exc))
    completion = verify_campaign_completion(config)
    campaign_attempt_state = campaign_attempt_blockers(completion)
    readiness = verify_run_day_readiness(config)
    blockers = []
    if platform.system() != "Darwin":
        blockers.append("diagnostic live controller requires macOS")
    if software.get("safari") != expected_safari:
        blockers.append(
            "Safari version differs from the frozen client: "
            f"expected {expected_safari}, observed {software.get('safari')!r}"
        )
    blockers.extend(name + " dependency is absent" for name, present in dependencies.items() if not present)
    if not hosts_clean:
        blockers.append("baseline /etc/hosts contains the Private Relay pin target or is unreadable")
    if unfinished:
        blockers.append("unfinished or invalid diagnostic attempt state exists")
    if grouped is not None:
        blockers.extend(safety_stop_reasons(grouped))
    blockers.extend(completion["blockers"])
    blockers.extend(campaign_attempt_state)
    blockers.extend(readiness["blockers"])
    interface = active_interface()
    if not interface:
        blockers.append("active default-route interface was not detected")
    ipv6 = ipv6_default_route_status()
    if not ipv6.get("confirmed_absent"):
        blockers.append("absence of an IPv6 default route is not confirmed")
    return {
        "recorded_utc": utc_now(),
        "status": "ready" if not blockers else "blocked",
        "blockers": blockers,
        "campaign_completion": completion,
        "normal_campaign_attempt_blockers": campaign_attempt_state,
        "run_day_http3_readiness": readiness,
        "dependencies": dependencies,
        "software": software,
        "expected_safari_version": expected_safari,
        "hosts_baseline_clean": hosts_clean,
        "hosts_entries": hosts_entries,
        "active_interface": interface,
        "ipv6_default_route": ipv6,
        "unfinished_attempts": unfinished,
    }


def privileged_anchor_checks(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    anchors = {
        "diagnostic": str(config["firewall"]["anchor"]),
        "normal_campaign": str(config["campaign_isolation"]["campaign_pf_anchor"]),
    }
    if anchors["diagnostic"] != "com.apple/icpr-protocol-diagnostic-v1":
        fail("diagnostic PF anchor differs from the dedicated frozen anchor")
    if anchors["normal_campaign"] != "com.apple/icpr-step9":
        fail("normal campaign PF anchor differs from the known campaign anchor")
    checks: dict[str, dict[str, Any]] = {}
    for label, anchor in anchors.items():
        rules = sudo_run(["/sbin/pfctl", "-a", anchor, "-sr"]).stdout.strip()
        checks[label] = {"anchor": anchor, "empty": not rules, "rules": rules}
    return checks


def require_empty_live_anchors(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sudo_ready()
    checks = privileged_anchor_checks(config)
    occupied = [label for label, check in checks.items() if not check["empty"]]
    if occupied:
        fail("PF anchor must be empty before diagnostic mutation: " + ", ".join(occupied))
    return checks


def acquire_lock(attempt_dir: Path) -> Any:
    locks = RUNTIME_ROOT / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    handle = (locks / f"{attempt_dir.name}.lock").open("a+")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def acquire_global_lock() -> Any:
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    handle = (RUNTIME_ROOT / "controller.lock").open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        fail("another protocol-diagnostic controller operation is active")
    return handle


def release_lock(handle: Any) -> None:
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    handle.close()


def start_watchdog(attempt_dir: Path, deadline: str) -> int:
    logs = RUNTIME_ROOT / "watchdogs"
    logs.mkdir(parents=True, exist_ok=True)
    log_handle = (logs / f"{attempt_dir.name}.log").open("ab")
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--series-profile",
            ACTIVE_SERIES_PROFILE,
            "_watchdog",
            str(attempt_dir),
            "--deadline-utc",
            deadline,
        ],
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    log_handle.close()
    (attempt_dir / "watchdog.pid").write_text(f"{process.pid}\n", encoding="utf-8")
    return process.pid


def stop_watchdog(attempt_dir: Path) -> None:
    path = attempt_dir / "watchdog.pid"
    if not path.is_file():
        return
    pid = int(path.read_text(encoding="utf-8").strip())
    if pid == os.getpid():
        path.unlink(missing_ok=True)
        return
    if process_running(pid):
        command = process_command(pid)
        if (
            "protocol_diag.py" not in command
            or "_watchdog" not in command
            or str(attempt_dir) not in command
        ):
            fail("watchdog PID was reused; refusing to signal it")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while process_running(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        if process_running(pid):
            fail("diagnostic watchdog did not stop")
    path.unlink(missing_ok=True)


def finalize_event(
    attempt_dir: Path,
    *,
    outcome: str,
    reason: str,
    condition_changed: bool,
    end_confirmation: str,
    cleanup_actions: list[str],
    mechanical_failure_code: str | None = None,
    safety_stop_code: str | None = None,
) -> None:
    metadata = attempt_metadata(attempt_dir)
    if safety_stop_code is not None and safety_stop_code not in SAFETY_STOP_CODES:
        fail(f"unknown diagnostic safety-stop code: {safety_stop_code}")
    allowed = set(metadata.get("retry_policy_allowed_codes", []))
    retry_authorized = (
        outcome in {"mechanical_failure", "prepare_error"}
        and mechanical_failure_code in allowed
    )
    append_jsonl(
        attempt_dir / "events.jsonl",
        {
            "event": "run_finished",
            "recorded_utc": utc_now(),
            "outcome": outcome,
            "reason": reason,
            "condition_changed": condition_changed,
            "end_condition_confirmation": end_confirmation,
            "cleanup_actions": cleanup_actions,
            "mechanical_failure_code": mechanical_failure_code,
            "retry_authorized": retry_authorized,
            "safety_stop_code": safety_stop_code,
        },
    )
    finalize_attempt(attempt_dir)


def cmd_snapshot_candidates(args: argparse.Namespace) -> int:
    if args.approve_dns_queries != DNS_QUERY_APPROVAL:
        fail(f"candidate collection requires --approve-dns-queries {DNS_QUERY_APPROVAL}")
    config, _ = load_configuration(Path(args.config))
    snapshot = collect_dns_snapshot(config, purpose=args.purpose)
    output = Path(args.output).expanduser().resolve()
    registered_reference_roots = tuple(
        get_series_profile(name).reference_root.resolve()
        for name in series_profile_names()
    )
    if not any(output.is_relative_to(root) for root in registered_reference_roots):
        fail("candidate snapshot output must remain under a registered series reference root")
    if output.exists() or output.with_name(output.name + ".sha256").exists():
        fail("candidate snapshot output already exists and will not be overwritten")
    write_json(output, snapshot, immutable=True)
    sidecar = write_sidecar(output)
    os.chmod(sidecar, 0o444)
    print(json.dumps({"path": str(output), "sha256": sha256_file(output), **snapshot}, indent=2))
    return 0


def _finalized_diagnostic_response_run_ids() -> list[str]:
    run_ids: list[str] = []
    for attempt_dir in attempt_directories():
        response_path = attempt_dir / "response.json"
        if not response_path.is_file():
            continue
        if not (attempt_dir / "manifest.sha256").is_file():
            fail(f"diagnostic response belongs to an unfinished attempt: {attempt_dir}")
        verify_attempt(attempt_dir)
        try:
            response = json.loads(response_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            fail(f"diagnostic response is unreadable: {response_path}: {exc}")
        run_id = str(response.get("run_id", ""))
        if not run_id or run_id != attempt_dir.name:
            fail(f"diagnostic response run ID does not match its attempt: {response_path}")
        run_ids.append(run_id)
    if not run_ids:
        fail("no finalized diagnostic response run IDs are available for final snapshotting")
    return sorted(set(run_ids))


def _ssh_read(ssh_key: Path, target: str, command: str) -> bytes:
    completed = subprocess.run(
        [
            "/usr/bin/ssh",
            "-i",
            str(ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            target,
            command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"read-only server evidence command failed ({completed.returncode}): {detail}")
    return completed.stdout


def cmd_snapshot_server_caddy(args: argparse.Namespace) -> int:
    if args.approve_server_snapshot != SERVER_SNAPSHOT_APPROVAL:
        fail(
            "active Caddy snapshot requires "
            f"--approve-server-snapshot {SERVER_SNAPSHOT_APPROVAL}"
        )
    config, _ = load_configuration(Path(args.config))
    settings = config.get("server", {}).get("live_caddy_snapshot", {})
    target = str(settings.get("ssh_target", ""))
    source = str(settings.get("source_path", ""))
    output_root = (REPO_ROOT / str(settings.get("output_root", ""))).resolve()
    expected_root = (REPO_ROOT / str(config["server"]["server_root"])).resolve()
    if (
        settings.get("capture_method") != "nonselective_active_log_byte_prefix_v1"
        or settings.get("require_nonselective_prefix") is not True
        or settings.get("active_pcap_snapshot_forbidden") is not True
    ):
        fail("configuration does not freeze the safe active-Caddy-only snapshot method")
    if not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+", target):
        fail("configured Caddy snapshot SSH target is invalid")
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", source):
        fail("configured active Caddy source path is invalid")
    try:
        output_root.relative_to(expected_root)
    except ValueError:
        fail("active Caddy snapshot output root is outside canonical server/recovery-data")
    ssh_key = Path(args.ssh_key).expanduser().resolve()
    if not ssh_key.is_file():
        fail(f"SSH identity file is absent: {ssh_key}")
    required_run_ids = sorted(set(args.required_run_id or []))
    if args.purpose == "diagnostic_final":
        if required_run_ids:
            fail("diagnostic_final derives run IDs from finalized attempts; do not supply them")
        required_run_ids = _finalized_diagnostic_response_run_ids()
    elif len(required_run_ids) != 1:
        fail("readiness snapshot requires exactly one --required-run-id")

    stat_command = f"sudo -n /usr/bin/stat -Lc '%d\t%i\t%s\t%Y\t%F' -- {source}"
    cat_command = f"sudo -n /bin/cat -- {source}"
    before = _parse_remote_caddy_stat(_ssh_read(ssh_key, target, stat_command))
    content = _ssh_read(ssh_key, target, cat_command)
    after = _parse_remote_caddy_stat(_ssh_read(ssh_key, target, stat_command))
    if before["device"] != after["device"] or before["inode"] != after["inode"]:
        fail("active Caddy log rotated during snapshot; retry the complete read")
    if not before["size_bytes"] <= len(content) <= after["size_bytes"]:
        fail("active Caddy bytes are not a complete prefix consistent with source stat records")
    row_count, counts = _validate_caddy_prefix_content(
        content, required_run_ids, args.purpose
    )

    captured_utc = utc_now()
    snapshot_id = (
        f"{captured_utc.replace('-', '').replace(':', '')}-"
        f"{sha256_bytes(content)[:12]}"
    )
    snapshot_dir = output_root / snapshot_id
    if snapshot_dir.exists():
        fail(f"immutable Caddy snapshot directory already exists: {snapshot_dir}")
    caddy_path = snapshot_dir / "access-prefix.jsonl"
    _write_immutable_bytes(caddy_path, content)
    caddy_sidecar = write_sidecar(caddy_path)
    os.chmod(caddy_sidecar, 0o440)
    provenance_path = snapshot_dir / "snapshot-provenance.json"
    provenance = {
        "schema_version": 1,
        "document_type": "icpr_live_caddy_prefix_snapshot",
        "status": "verified",
        "purpose": args.purpose,
        "capture_method": "nonselective_active_log_byte_prefix_v1",
        "source_nonselective_prefix": True,
        "source_mutated": False,
        "active_pcap_copied": False,
        "ssh_target": target,
        "source_path": source,
        "captured_utc": captured_utc,
        "source_stat_before": before,
        "source_stat_after": after,
        "prefix_bytes": len(content),
        "row_count": row_count,
        "required_run_ids": required_run_ids,
        "matched_run_id_counts": counts,
        "snapshot_path": _repo_relative(caddy_path),
        "snapshot_sha256": sha256_file(caddy_path),
    }
    write_json(provenance_path, provenance, immutable=True)
    provenance_sidecar = write_sidecar(provenance_path)
    os.chmod(provenance_sidecar, 0o440)
    print(
        json.dumps(
            {
                "status": "verified",
                "caddy_path": _repo_relative(caddy_path),
                "caddy_sha256": provenance["snapshot_sha256"],
                "provenance_path": _repo_relative(provenance_path),
                "provenance_sha256": sha256_file(provenance_path),
                "required_run_id_counts": counts,
                "next": "wait for normal hourly pcap rotation, then run the established server backup/pull",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    config, config_hash = load_configuration(Path(args.config))
    plan, plan_hash = load_plan(Path(args.plan), config_hash)
    report = campaign_preflight(config, plan, plan_hash)
    if args.candidate_snapshot:
        try:
            snapshot, digest = verify_candidate_snapshot(
                Path(args.candidate_snapshot), config, require_run_day=True
            )
            report["candidate_snapshot"] = {
                "ready": True,
                "sha256": digest,
                "recorded_utc": snapshot["recorded_utc"],
                "capture_candidates": snapshot["capture_candidates"],
            }
        except IcprError as exc:
            report["candidate_snapshot"] = {"ready": False, "error": str(exc)}
            report["blockers"].append(str(exc))
            report["status"] = "blocked"
    if args.privileged:
        sudo_ready()
        checks = privileged_anchor_checks(config)
        report["privileged_anchor_checks"] = checks
        for label, check in checks.items():
            if not check["empty"]:
                report["blockers"].append(f"{label} PF anchor is not empty")
                report["status"] = "blocked"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "ready" else 2


def cmd_validate_pf(args: argparse.Namespace) -> int:
    config, _ = load_configuration(Path(args.config))
    interface = args.interface or active_interface()
    if not interface:
        fail("active default-route interface was not detected")
    rule = render_pf_rule(config, interface)
    validate_rendered_pf_rule(rule, config, interface)
    report: dict[str, Any] = {
        "interface": interface,
        "anchor": config["firewall"]["anchor"],
        "rule": rule,
        "structurally_valid": True,
        "system_parser_invoked": bool(args.system_parser),
    }
    if args.system_parser:
        report["system_parser"] = system_validate_pf_rule(rule)
        if not report["system_parser"]["valid"]:
            print(json.dumps(report, indent=2))
            return 2
    print(json.dumps(report, indent=2))
    return 0


def cmd_rehearse_cleanup(args: argparse.Namespace) -> int:
    lock = acquire_global_lock()
    try:
        return _cmd_rehearse_cleanup_locked(args)
    finally:
        release_lock(lock)


def _cmd_rehearse_cleanup_locked(args: argparse.Namespace) -> int:
    """Disruptively exercise only pin/PF restoration, without Safari or a trial."""
    config, config_hash = load_configuration(Path(args.config))
    plan, plan_hash = load_plan(Path(args.plan), config_hash)
    report = campaign_preflight(config, plan, plan_hash)
    if report["status"] != "ready":
        fail("cleanup rehearsal is blocked: " + "; ".join(report["blockers"]))
    if args.approve_rehearsal != "REHEARSE_DIAGNOSTIC_CLEANUP":
        fail("cleanup rehearsal requires --approve-rehearsal REHEARSE_DIAGNOSTIC_CLEANUP")
    if args.approve_dns != DNS_APPROVAL:
        fail(f"cleanup rehearsal requires --approve-dns {DNS_APPROVAL}")
    if args.approve_firewall != FIREWALL_APPROVAL:
        fail(f"cleanup rehearsal requires --approve-firewall {FIREWALL_APPROVAL}")
    if args.approve_disruptive != DISRUPTIVE_APPROVAL:
        fail(f"cleanup rehearsal requires --approve-disruptive {DISRUPTIVE_APPROVAL}")
    interface = active_interface()
    if not interface:
        fail("active default-route interface was not detected")
    require_empty_live_anchors(config)
    rehearsal_id = "cleanup-rehearsal-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = REFERENCE_ROOT / rehearsal_id
    directory.mkdir(parents=True, exist_ok=False)
    baseline = Path("/etc/hosts").read_bytes()
    write_json(
        directory / "metadata.json",
        {
            "document_type": "icpr_protocol_diagnostic_cleanup_rehearsal",
            "rehearsal_id": rehearsal_id,
            "started_utc": utc_now(),
            "config_sha256": config_hash,
            "plan_sha256": plan_hash,
            "interface": interface,
            "hosts_baseline_sha256": sha256_bytes(baseline),
            "counted_observation": False,
            "safari_opened": False,
        },
    )
    actions: list[str] = []
    try:
        prepare_firewall(directory, config, condition="udp_blocked", interface=interface)
        apply_dns_pin(directory, config)
    finally:
        actions = cleanup_attempt(directory)
    restored = Path("/etc/hosts").read_bytes()
    sudo_ready()
    remaining_rules = sudo_run(
        ["/sbin/pfctl", "-a", str(config["firewall"]["anchor"]), "-sr"]
    ).stdout.strip()
    result = {
        "finished_utc": utc_now(),
        "hosts_restored_byte_for_byte": restored == baseline,
        "hosts_restored_sha256": sha256_bytes(restored),
        "pf_anchor_empty_after_cleanup": not remaining_rules,
        "pf_remaining_rules": remaining_rules,
        "cleanup_actions": actions,
    }
    write_json(directory / "result.json", result)
    if not result["hosts_restored_byte_for_byte"] or not result["pf_anchor_empty_after_cleanup"]:
        fail("cleanup rehearsal did not restore both hosts and dedicated PF state")
    finalize_attempt(directory)
    print(json.dumps({"path": str(directory), **result}, indent=2))
    return 0


def existing_candidate_hash(plan_hash: str) -> str | None:
    values = {
        str(attempt_metadata(path).get("candidate_snapshot_sha256"))
        for path in attempt_directories()
        if attempt_metadata(path).get("plan_sha256") == plan_hash
    }
    values.discard("None")
    if len(values) > 1:
        fail("existing diagnostic attempts reference multiple candidate snapshots")
    return next(iter(values), None)


def cmd_prepare(args: argparse.Namespace) -> int:
    lock = acquire_global_lock()
    try:
        return _cmd_prepare_locked(args)
    finally:
        release_lock(lock)


def _cmd_prepare_locked(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    plan_path = Path(args.plan)
    config, config_hash = load_configuration(config_path)
    plan, plan_hash = load_plan(plan_path, config_hash)
    report = campaign_preflight(config, plan, plan_hash)
    if report["status"] != "ready":
        fail("diagnostic live start is blocked: " + "; ".join(report["blockers"]))
    if args.approve_live != LIVE_APPROVAL:
        fail(f"live diagnostic requires --approve-live {LIVE_APPROVAL}")
    if args.approve_dns != DNS_APPROVAL:
        fail(f"diagnostic pin requires --approve-dns {DNS_APPROVAL}")
    if args.approve_disruptive != DISRUPTIVE_APPROVAL:
        fail(f"diagnostic reset requires --approve-disruptive {DISRUPTIVE_APPROVAL}")
    if args.condition == "udp_blocked" and args.approve_firewall != FIREWALL_APPROVAL:
        fail(f"blocked condition requires --approve-firewall {FIREWALL_APPROVAL}")
    if args.clock_status != "synchronized":
        fail("diagnostic requires synchronized clock status")
    if subprocess.run(["pgrep", "-x", "Safari"], stdout=subprocess.DEVNULL, check=False).returncode == 0:
        fail("Safari must be fully quit before every diagnostic trial")
    validate_slot_request(
        plan,
        plan_hash,
        slot_id=args.slot_id,
        retry_number=args.retry_number,
        condition=args.condition,
    )
    snapshot_path = Path(args.candidate_snapshot).expanduser().resolve()
    snapshot, snapshot_hash = verify_candidate_snapshot(
        snapshot_path, config, require_run_day=True
    )
    prior_hash = existing_candidate_hash(plan_hash)
    if prior_hash and prior_hash != snapshot_hash:
        fail("all ten diagnostic slots must use the same frozen candidate snapshot")
    if not prior_hash:
        age = (
            dt.datetime.now(dt.timezone.utc) - parse_utc(str(snapshot["recorded_utc"]))
        ).total_seconds()
        if age < 0 or age > int(config["dns"]["first_slot_snapshot_max_age_seconds"]):
            fail("first diagnostic slot candidate snapshot is older than the frozen limit")
    started = utc_now()
    day = started[:10]
    if parse_utc(str(snapshot["recorded_utc"])).date().isoformat() != day:
        fail("UTC day changed after candidate verification; freeze a new run-day snapshot")
    readiness_completed = report.get("run_day_http3_readiness", {}).get("completed_utc")
    if not isinstance(readiness_completed, str) or parse_utc(readiness_completed).date().isoformat() != day:
        fail("UTC day changed after readiness verification; repeat the non-counted readiness check")
    feed_path, feed_hash = feed_for_day(day)
    asn_path, asn_hash, asn_row = dated_pin_mapping(day, config)
    interface = active_interface()
    if not interface:
        fail("active default-route interface was not detected")
    require_empty_live_anchors(config)
    software = software_snapshot()
    expected_safari = str(config["fixed_conditions"]["safari_client"])
    if expected_safari.startswith("Safari "):
        expected_safari = expected_safari.removeprefix("Safari ")
    if software.get("safari") != expected_safari:
        fail("Safari version changed after preflight")
    gate_session_id = validate_gate_session_request(
        args.series_profile, args.gate_session_id
    )
    gate_pre: dict[str, Any] | None = None
    gate_arm_hash: str | None = None
    controls_ready_hash: str | None = None
    if gate_session_id:
        _, controls_ready_hash = _load_controls_ready(gate_session_id)
        arm_path = REFERENCE_ROOT / "gates" / gate_session_id / "arm.json"
        arm_value, gate_arm_hash = load_hash_verified_json(arm_path)
        if arm_value.get("session_id") != gate_session_id:
            fail("origin-gate arm evidence is bound to another session")
        try:
            gate_pre = _gate_client_for_key(args.gate_ssh_key, config).snapshot(
                gate_session_id
            )
        except Exception as exc:
            fail(f"H3-required pre-slot origin-gate snapshot failed: {exc}")
    run_id = generate_run_id()
    attempt_dir = CLIENT_ROOT / day / run_id
    attempt_dir.mkdir(parents=True, exist_ok=False)
    origin = str(config["server"]["public_ipv4"])
    candidates = list(snapshot["capture_candidates"])
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "document_type": "icpr_protocol_diagnostic_attempt",
        "diagnostic_id": plan["diagnostic_id"],
        "analysis_family": plan.get("analysis_family", "dual_protocol"),
        "run_id": run_id,
        "slot_id": args.slot_id,
        "sequence_number": next(slot["sequence_number"] for slot in plan["slots"] if slot["slot_id"] == args.slot_id),
        "retry_number": args.retry_number,
        "condition": args.condition,
        "client_start_utc": started,
        "clock_status": args.clock_status,
        "private_relay_state": config["fixed_conditions"]["private_relay_state"],
        "location_setting": config["fixed_conditions"]["location_setting"],
        "intended_ingress_group": config["fixed_conditions"]["ingress_group"],
        "intended_ingress_ipv4": config["fixed_conditions"]["intended_ingress_ipv4"],
        "intended_ingress_ip": config["fixed_conditions"]["intended_ingress_ipv4"],
        "intended_ingress_asn": config["fixed_conditions"]["intended_ingress_asn"],
        "origin_public_ipv4": origin,
        "real_public_ipv4": str(ipaddress.IPv4Address(args.real_public_ip)),
        "active_interface": interface,
        "capture_candidates": candidates,
        "ingress_candidates": [value for value in candidates if value != origin],
        "candidate_hostname_map": snapshot["candidate_hostname_map"],
        "candidate_snapshot_path": str(snapshot_path.relative_to(REPO_ROOT)),
        "candidate_snapshot_sha256": snapshot_hash,
        "apple_feed_path": str(feed_path.relative_to(REPO_ROOT)),
        "apple_feed_sha256": feed_hash,
        "origin_asn_path": str(asn_path.relative_to(REPO_ROOT)),
        "origin_asn_sha256": asn_hash,
        "fixed_pin_origin_mapping": asn_row,
        "config_path": str(config_path.resolve().relative_to(REPO_ROOT)),
        "config_sha256": config_hash,
        "plan_path": str(plan_path.resolve().relative_to(REPO_ROOT)),
        "plan_sha256": plan_hash,
        "operator_condition_confirmation": args.condition_confirmation,
        "software_start": software,
        "macos_version": software.get("macos"),
        "safari_version": software.get("safari"),
        "python_version": software.get("python"),
        "retry_policy_allowed_codes": config["retry_policy"]["allowed_only_for_codes"],
        "url": config["server"]["url_template"].format(run_id=run_id),
    }
    if gate_session_id and gate_pre is not None:
        gate_pre_path = attempt_dir / "origin-gate-pre.json"
        write_json(gate_pre_path, gate_pre, immutable=True)
        write_sidecar(gate_pre_path)
        metadata.update(
            {
                "gate_session_id": gate_session_id,
                "gate_arm_sha256": gate_arm_hash,
                "controls_ready_sha256": controls_ready_hash,
                "gate_ssh_key": str(Path(args.gate_ssh_key).expanduser().resolve()),
                "origin_gate_pre_sha256": sha256_file(gate_pre_path),
            }
        )
    write_json(attempt_dir / "metadata.json", metadata)
    append_jsonl(attempt_dir / "events.jsonl", {"event": "run_started", "recorded_utc": started, **metadata})
    stage = "initialization"
    try:
        sudo_ready()
        stage = "clock_check"
        network_time = sudo_run(["/usr/sbin/systemsetup", "-getusingnetworktime"]).stdout.strip()
        if "On" not in network_time:
            fail("macOS network time is not enabled")
        write_json(attempt_dir / "clock-status.json", {"recorded_utc": utc_now(), "network_time": network_time})
        bpf = capture_filter(candidates)
        metadata["capture_filter"] = bpf
        write_json(attempt_dir / "metadata.json", metadata)
        stage = "capture_start"
        start_capture(attempt_dir, interface, bpf, int(config["capture"]["snaplen_bytes"]))
        stage = "firewall_prepare"
        prepare_firewall(attempt_dir, config, condition=args.condition, interface=interface)
        stage = "dns_pin_and_proxy_reset"
        apply_dns_pin(attempt_dir, config)
        stage = "safari_launch"
        launch = utc_now()
        response_deadline = (
            parse_utc(launch)
            + dt.timedelta(seconds=int(config["timeouts"]["browser_response_deadline_seconds"]))
        ).isoformat().replace("+00:00", "Z")
        operator_deadline = (
            parse_utc(launch)
            + dt.timedelta(seconds=int(config["timeouts"]["operator_completion_grace_seconds"]))
        ).isoformat().replace("+00:00", "Z")
        metadata["safari_launch_requested_utc"] = launch
        metadata["response_deadline_utc"] = response_deadline
        metadata["operator_completion_deadline_utc"] = operator_deadline
        write_json(attempt_dir / "metadata.json", metadata)
        append_jsonl(attempt_dir / "events.jsonl", {"event": "safari_url_launch_requested", "recorded_utc": launch, "url": metadata["url"]})
        start_watchdog(attempt_dir, operator_deadline)
        result = subprocess.run(["/usr/bin/open", "-a", "Safari", metadata["url"]], check=False)
        if result.returncode != 0:
            fail("Safari URL launch was not issued")
        append_jsonl(attempt_dir / "events.jsonl", {"event": "safari_url_opened", "recorded_utc": utc_now(), "url": metadata["url"]})
    except BaseException as exc:
        try:
            stop_watchdog(attempt_dir)
        except Exception:
            pass
        actions: list[str] = []
        cleanup_error: Exception | None = None
        try:
            actions = cleanup_attempt(attempt_dir)
        except Exception as caught:
            cleanup_error = caught
        code = None
        safety_stop_code = None
        if stage == "capture_start":
            code = "CAPTURE_START_FAILED"
        elif stage == "safari_launch":
            code = "SAFARI_LAUNCH_NOT_ISSUED"
        elif stage == "clock_check":
            safety_stop_code = "CLOCK_OR_EVIDENCE_INTEGRITY_UNRELIABLE"
        elif stage == "firewall_prepare":
            safety_stop_code = "PF_RULE_SCOPE_OR_STATE_UNRELIABLE"
        elif stage == "dns_pin_and_proxy_reset":
            safety_stop_code = "DNS_PIN_OR_RESTORATION_UNRELIABLE"
        if cleanup_error is None:
            finalize_event(
                attempt_dir,
                outcome="prepare_error",
                reason=f"{stage}: {exc}",
                condition_changed=False,
                end_confirmation="unavailable: prepare failed before a completed navigation",
                cleanup_actions=actions,
                mechanical_failure_code=code,
                safety_stop_code=safety_stop_code,
            )
        else:
            append_jsonl(attempt_dir / "events.jsonl", {"event": "prepare_error_cleanup_failed", "recorded_utc": utc_now(), "reason": str(cleanup_error)})
        raise
    print(json.dumps({"run_id": run_id, "attempt_dir": str(attempt_dir), "url": metadata["url"], "response_deadline_utc": metadata["response_deadline_utc"], "operator_completion_deadline_utc": metadata["operator_completion_deadline_utc"]}, indent=2))
    return 0


def finish_attempt(
    attempt_dir: Path,
    *,
    outcome: str,
    reason: str,
    response_file: str | None,
    mechanical_failure_code: str | None,
    condition_changed: bool,
    end_confirmation: str,
    safety_stop_code: str | None = None,
) -> int:
    lock = acquire_lock(attempt_dir)
    try:
        if (attempt_dir / "manifest.sha256").is_file():
            fail("diagnostic attempt is already finalized")
        metadata = attempt_metadata(attempt_dir)
        requested_mechanical_code = mechanical_failure_code
        if requested_mechanical_code in {
            "CAPTURE_START_FAILED",
            "CAPTURE_RUNTIME_FAILED",
            "SAFARI_LAUNCH_NOT_ISSUED",
        }:
            fail(
                f"{requested_mechanical_code} is controller-detected only and cannot be operator supplied"
            )
        if requested_mechanical_code == "RESPONSE_EVIDENCE_NOT_SAVED" and (
            response_file is not None or (attempt_dir / "response.json").exists()
        ):
            fail("RESPONSE_EVIDENCE_NOT_SAVED requires response.json to be absent")
        if response_file:
            response = json.loads(Path(response_file).expanduser().read_text(encoding="utf-8"))
            if response.get("run_id") != metadata["run_id"]:
                fail("response run_id does not match the diagnostic attempt")
            source = Path(response_file).expanduser()
            response_bytes = source.read_bytes()
            response = json.loads(response_bytes)
            response_path = attempt_dir / "response.json"
            if response_path.exists():
                fail("diagnostic response evidence already exists and will not be overwritten")
            response_path.write_bytes(response_bytes)
            remote_ip = str(response.get("remote_ip", ""))
            bypass = remote_ip == metadata["real_public_ipv4"]
            if bypass:
                outcome = "direct_bypass"
                reason = "controlled origin observed the recorded real client IPv4"
            server_ms = response.get("server_unix_ms")
            if isinstance(server_ms, int):
                server_time = dt.datetime.fromtimestamp(server_ms / 1000, tz=dt.timezone.utc)
                if not bypass and server_time > parse_utc(metadata["response_deadline_utc"]):
                    outcome = "timeout"
                    reason = "tagged response arrived after the frozen 90-second deadline"
        elif outcome == "success":
            fail("successful diagnostic finish requires an exact response file")
        attempt_profile: SeriesProfile | None = None
        profile_resolution_error: str | None = None
        try:
            attempt_profile = get_profile_for_analysis_family(
                str(metadata.get("analysis_family", "dual_protocol"))
            )
        except ValueError as exc:
            profile_resolution_error = str(exc)
        if attempt_profile is not None and attempt_profile.requires_origin_gate:
            try:
                attempt_config = load_attempt_configuration(metadata)
                gate_post = _gate_client_for_key(
                    str(metadata["gate_ssh_key"]), attempt_config
                ).snapshot(str(metadata["gate_session_id"]))
                gate_post_path = attempt_dir / "origin-gate-post.json"
                write_json(gate_post_path, gate_post, immutable=True)
                write_sidecar(gate_post_path)
            except Exception as exc:
                condition_changed = True
                safety_stop_code = safety_stop_code or "SERVER_EVIDENCE_UNAVAILABLE"
                write_json(
                    attempt_dir / "origin-gate-post-error.json",
                    {"recorded_utc": utc_now(), "error": str(exc)},
                    immutable=True,
                )
        lifecycle_errors: list[str] = []
        try:
            stop_watchdog(attempt_dir)
        except Exception as exc:
            lifecycle_errors.append(f"watchdog stop failed: {exc}")
        actions: list[str] = []
        try:
            actions = cleanup_attempt(attempt_dir)
        except Exception as exc:
            lifecycle_errors.append(f"attempt cleanup failed: {exc}")
        if lifecycle_errors:
            append_jsonl(
                attempt_dir / "events.jsonl",
                {
                    "event": "finish_cleanup_incomplete",
                    "recorded_utc": utc_now(),
                    "errors": lifecycle_errors,
                },
            )
            if profile_resolution_error:
                lifecycle_errors.append(profile_resolution_error)
            fail("; ".join(lifecycle_errors))
        if profile_resolution_error:
            fail(profile_resolution_error)
        capture_state = json.loads(
            (attempt_dir / "capture-state.json").read_text(encoding="utf-8")
        )
        capture_runtime_failed = bool(capture_state.get("premature_exit_detected_utc"))
        if (
            capture_runtime_failed
            and outcome != "direct_bypass"
            and not condition_changed
            and not safety_stop_code
        ):
            outcome = "mechanical_failure"
            mechanical_failure_code = "CAPTURE_RUNTIME_FAILED"
            reason = "client capture exited after confirmed start and before requested stop"
        allowed_codes = set(metadata["retry_policy_allowed_codes"])
        if outcome == "mechanical_failure" and mechanical_failure_code not in allowed_codes:
            fail("mechanical failure code is absent or not in the frozen retry policy")
        if outcome != "mechanical_failure" and mechanical_failure_code:
            fail("mechanical failure code is valid only with mechanical_failure outcome")
        if mechanical_failure_code and safety_stop_code:
            fail("mechanical retry and safety-stop codes are mutually exclusive")
        finish_interface = active_interface()
        finish_software = software_snapshot()
        finish_ipv6 = ipv6_default_route_status()
        automatic_changes = []
        if finish_interface != metadata.get("active_interface"):
            automatic_changes.append("active_interface")
        if finish_software.get("macos") != metadata.get("macos_version"):
            automatic_changes.append("macos_version")
        if finish_software.get("safari") != metadata.get("safari_version"):
            automatic_changes.append("safari_version")
        if not finish_ipv6.get("confirmed_absent"):
            automatic_changes.append("ipv6_default_route")
        write_json(
            attempt_dir / "finish-condition.json",
            {
                "recorded_utc": utc_now(),
                "active_interface": finish_interface,
                "software_end": finish_software,
                "ipv6_default_route": finish_ipv6,
                "capture_runtime_failed": capture_runtime_failed,
                "operator_confirmation": end_confirmation,
                "automatic_changes": automatic_changes,
            },
        )
        finalize_event(
            attempt_dir,
            outcome=outcome,
            reason=reason,
            condition_changed=condition_changed or bool(automatic_changes),
            end_confirmation=end_confirmation,
            cleanup_actions=actions,
            mechanical_failure_code=mechanical_failure_code,
            safety_stop_code=safety_stop_code,
        )
    finally:
        release_lock(lock)
    print(json.dumps({"run_id": attempt_dir.name, "outcome": outcome, "finalized": True}, indent=2))
    return 3 if outcome == "direct_bypass" else 0


def cmd_finish(args: argparse.Namespace) -> int:
    return finish_attempt(
        find_attempt(args.attempt),
        outcome=args.outcome,
        reason=args.reason,
        response_file=args.response_file,
        mechanical_failure_code=None,
        condition_changed=args.condition_changed,
        end_confirmation=args.end_condition_confirmation,
        safety_stop_code=None,
    )


def cmd_abort(args: argparse.Namespace) -> int:
    outcome = "mechanical_failure" if args.mechanical_failure_code else "aborted"
    return finish_attempt(
        find_attempt(args.attempt),
        outcome=outcome,
        reason=args.reason,
        response_file=None,
        mechanical_failure_code=args.mechanical_failure_code,
        condition_changed=args.condition_changed,
        end_confirmation=args.end_condition_confirmation,
        safety_stop_code=args.safety_stop_code,
    )


def cmd_cleanup(args: argparse.Namespace) -> int:
    attempt_dir = find_attempt(args.attempt)
    lock = acquire_lock(attempt_dir)
    try:
        if (attempt_dir / "manifest.sha256").is_file():
            verify_attempt(attempt_dir)
            print(json.dumps({"attempt": str(attempt_dir), "already_finalized": True}, indent=2))
            return 0
        recovery_errors: list[str] = []
        try:
            stop_watchdog(attempt_dir)
        except Exception as exc:
            recovery_errors.append(f"watchdog stop failed: {exc}")
        actions: list[str] = []
        try:
            actions = cleanup_attempt(attempt_dir)
        except Exception as exc:
            recovery_errors.append(f"attempt cleanup failed: {exc}")
        if recovery_errors:
            append_jsonl(
                attempt_dir / "events.jsonl",
                {
                    "event": "manual_cleanup_incomplete",
                    "recorded_utc": utc_now(),
                    "errors": recovery_errors,
                },
            )
            fail("; ".join(recovery_errors))
        finished = read_finished_event(attempt_dir)
        if not finished:
            finalize_event(
                attempt_dir,
                outcome="prepare_error",
                reason="manual recovery after interrupted diagnostic preparation",
                condition_changed=False,
                end_confirmation="unavailable: recovered by cleanup",
                cleanup_actions=actions,
                mechanical_failure_code=None,
            )
        else:
            # Recovery may arrive after run_finished was durably appended but
            # before the manifest/sidecar transaction completed. Cleanup above
            # has re-verified restoration; hash-finalize that one existing event
            # instead of appending a second lifecycle outcome.
            finalize_attempt(attempt_dir)
    finally:
        release_lock(lock)
    print(json.dumps({"attempt": str(attempt_dir), "cleanup_actions": actions}, indent=2))
    return 0


def cmd_watchdog(args: argparse.Namespace) -> int:
    attempt_dir = find_attempt(args.attempt)
    deadline = parse_utc(args.deadline_utc)
    while dt.datetime.now(dt.timezone.utc) < deadline:
        if (attempt_dir / "manifest.sha256").is_file():
            return 0
        subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        remaining = (deadline - dt.datetime.now(dt.timezone.utc)).total_seconds()
        time.sleep(max(1, min(30, remaining)))
    lock = acquire_lock(attempt_dir)
    try:
        if (attempt_dir / "manifest.sha256").is_file():
            return 0
        actions = cleanup_attempt(attempt_dir, noninteractive=True)
        (attempt_dir / "watchdog.pid").unlink(missing_ok=True)
        finalize_event(
            attempt_dir,
            outcome="operator_completion_timeout",
            reason="operator completion grace expired; watchdog restored temporary state",
            condition_changed=False,
            end_confirmation="unavailable: watchdog cleanup",
            cleanup_actions=actions,
        )
    finally:
        release_lock(lock)
    return 0


def pairing_policy(args: argparse.Namespace) -> dict[str, Any]:
    profile = get_series_profile(args.series_profile)
    return {
        "allowed_client_root": profile.client_root,
        "allowed_derived_root": profile.derived_root,
        "analysis_family": profile.analysis_family,
    }


def _require_origin_gate_profile(args: argparse.Namespace) -> None:
    profile = get_series_profile(args.series_profile)
    if not profile.requires_origin_gate:
        fail("origin-gate commands require an origin-gated diagnostic profile")


def validate_gate_session_request(profile_name: str, value: str | None) -> str | None:
    profile = get_series_profile(profile_name)
    if not profile.requires_origin_gate:
        if value:
            fail("non-gated attempts cannot reference an H3 origin gate")
        return None
    if not value or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", value):
        fail("origin-gated attempts require one valid --gate-session-id")
    return value


def _gate_client(args: argparse.Namespace) -> Any:
    config, _ = load_configuration(Path(args.config))
    return _gate_client_for_key(args.ssh_key, config)


def _gate_client_for_key(key_path: str, config: dict[str, Any]) -> Any:
    from server_gate import ServerGateClient

    server = config.get("server")
    if not isinstance(server, dict):
        fail("diagnostic configuration lacks server settings")
    live_snapshot = server.get("live_caddy_snapshot")
    if not isinstance(live_snapshot, dict):
        fail("diagnostic configuration lacks live Caddy snapshot settings")
    ssh_target = live_snapshot.get("ssh_target")
    if not isinstance(ssh_target, str) or not ssh_target:
        fail("diagnostic configuration lacks the gate SSH target")
    return ServerGateClient(
        host=ssh_target,
        key_path=Path(key_path),
        helper_path="/usr/local/sbin/icpr-h3-origin-gate",
        policy=origin_gate_policy(config),
    )


def _write_gate_artifact(session_id: str, name: str, value: dict[str, Any]) -> Path:
    directory = REFERENCE_ROOT / "gates" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    write_json(path, value, immutable=True)
    write_sidecar(path)
    return path


def cmd_gate_validate(args: argparse.Namespace) -> int:
    _require_origin_gate_profile(args)
    if args.approve_gate_validation != GATE_VALIDATE_APPROVAL:
        fail(f"gate validation requires --approve-gate-validation {GATE_VALIDATE_APPROVAL}")
    value = _gate_client(args).validate(args.session_id)
    value.update({"recorded_utc": utc_now(), "action": "validate", "counted": False})
    path = _write_gate_artifact(args.session_id, "validation.json", value)
    print(json.dumps({"path": str(path), **value}, indent=2, sort_keys=True))
    return 0


def cmd_gate_arm(args: argparse.Namespace) -> int:
    _require_origin_gate_profile(args)
    if args.approve_origin_gate != GATE_ARM_APPROVAL:
        fail(f"gate activation requires --approve-origin-gate {GATE_ARM_APPROVAL}")
    validation_path = REFERENCE_ROOT / "gates" / args.session_id / "validation.json"
    load_hash_verified_json(validation_path)
    value = _gate_client(args).arm(args.session_id)
    value.update({"recorded_utc": utc_now(), "action": "arm", "counted": False})
    path = _write_gate_artifact(args.session_id, "arm.json", value)
    print(json.dumps({"path": str(path), **value}, indent=2, sort_keys=True))
    return 0


def cmd_gate_status(args: argparse.Namespace) -> int:
    _require_origin_gate_profile(args)
    value = _gate_client(args).snapshot(args.session_id)
    value.update({"recorded_utc": utc_now(), "action": "status", "counted": False})
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = _write_gate_artifact(args.session_id, f"status-{stamp}.json", value)
    print(json.dumps({"path": str(path), **value}, indent=2, sort_keys=True))
    return 0


def cmd_gate_disarm(args: argparse.Namespace) -> int:
    _require_origin_gate_profile(args)
    if args.approve_origin_gate_removal != GATE_DISARM_APPROVAL:
        fail(
            "gate removal requires --approve-origin-gate-removal "
            + GATE_DISARM_APPROVAL
        )
    value = _gate_client(args).disarm(args.session_id)
    value.update({"recorded_utc": utc_now(), "action": "disarm", "counted": False})
    path = _write_gate_artifact(args.session_id, "disarm.json", value)
    print(json.dumps({"path": str(path), **value}, indent=2, sort_keys=True))
    return 0


def _load_controls_ready(session_id: str) -> tuple[dict[str, Any], str]:
    from h3_controls import ControlError, validate_controls_ready

    directory = REFERENCE_ROOT / "controls" / session_id
    ready, ready_hash = load_hash_verified_json(directory / "controls-ready-v1.json")
    controls: dict[str, dict[str, Any]] = {}
    for key, filename in (
        ("warmup", "warmup.json"),
        ("tcp_control", "tcp-control.json"),
        ("pre_h3_control", "pre-h3-control.json"),
    ):
        value, digest = load_hash_verified_json(directory / filename)
        if ready.get("control_hashes", {}).get(key) != digest:
            fail(f"controls-ready hash differs for {key}")
        controls[key] = value
    try:
        validated = validate_controls_ready(controls, session_id)
    except ControlError as exc:
        fail(str(exc))
    if ready.get("status") != "ready" or ready.get("gate_session_id") != session_id:
        fail("controls-ready attestation is not bound to the active gate session")
    return validated, ready_hash


def cmd_verify_controls(args: argparse.Namespace) -> int:
    from h3_controls import ControlError, validate_controls_ready

    _require_origin_gate_profile(args)
    session_id = validate_gate_session_request(args.series_profile, args.session_id)
    assert session_id is not None
    inputs: dict[str, dict[str, Any]] = {}
    source_hashes: dict[str, str] = {}
    for key, filename in (
        ("warmup", args.warmup_file),
        ("tcp_control", args.tcp_control_file),
        ("pre_h3_control", args.pre_h3_control_file),
    ):
        loaded, digest = load_hash_verified_json(Path(filename).expanduser().resolve())
        inputs[key] = loaded
        source_hashes[key] = digest
    try:
        ready = validate_controls_ready(inputs, session_id)
    except ControlError as exc:
        fail(str(exc))
    directory = REFERENCE_ROOT / "controls" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    control_hashes: dict[str, str] = {}
    for key, filename in (
        ("warmup", "warmup.json"),
        ("tcp_control", "tcp-control.json"),
        ("pre_h3_control", "pre-h3-control.json"),
    ):
        path = directory / filename
        write_json(path, inputs[key], immutable=True)
        write_sidecar(path)
        control_hashes[key] = sha256_file(path)
    ready.update(
        {
            "recorded_utc": utc_now(),
            "control_hashes": control_hashes,
            "source_hashes": source_hashes,
        }
    )
    path = directory / "controls-ready-v1.json"
    write_json(path, ready, immutable=True)
    write_sidecar(path)
    print(json.dumps({"path": str(path), **ready}, indent=2, sort_keys=True))
    return 0


def cmd_pair(args: argparse.Namespace) -> int:
    from pairing import run

    try:
        config, _ = load_configuration(Path(args.config))
        policy = pairing_policy(args)
        report = run(
            client_root=Path(args.client_root),
            server_root=Path(args.server_root),
            derived_root=Path(args.derived_root),
            server_private_ip=configured_server_private_ipv4(config),
            **policy,
        )
    except PairingError as exc:
        fail(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


class SeriesArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, default_series_profile: str = "dual_protocol", **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.default_series_profile = default_series_profile

    def parse_args(
        self, args: Any = None, namespace: argparse.Namespace | None = None
    ) -> argparse.Namespace:
        parsed = super().parse_args(args, namespace)
        profile = get_series_profile(parsed.series_profile)
        for attribute, value in (
            ("config", profile.config_path),
            ("plan", profile.plan_path),
            ("client_root", profile.client_root),
            ("derived_root", profile.derived_root),
        ):
            if hasattr(parsed, attribute) and getattr(parsed, attribute) is None:
                setattr(parsed, attribute, str(value))
        parsed.runtime_root = profile.runtime_root
        parsed.reference_root = profile.reference_root
        return parsed


def parser(default_profile: str = "dual_protocol") -> argparse.ArgumentParser:
    root = SeriesArgumentParser(
        description=__doc__, default_series_profile=default_profile
    )
    root.add_argument(
        "--series-profile",
        choices=series_profile_names(),
        default=default_profile,
        help="select isolated configuration, plan, and output roots",
    )
    sub = root.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight", help="read-only diagnostic launch-gate checks")
    preflight.add_argument("--config")
    preflight.add_argument("--plan")
    preflight.add_argument("--candidate-snapshot")
    preflight.add_argument("--privileged", action="store_true")
    preflight.set_defaults(function=cmd_preflight)

    snapshot = sub.add_parser("snapshot-candidates", help="freeze current DNS/effective-resolver candidates")
    snapshot.add_argument("--config")
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument("--purpose", choices=["design_review", "run_day"], required=True)
    snapshot.add_argument("--approve-dns-queries")
    snapshot.set_defaults(function=cmd_snapshot_candidates)

    server_snapshot = sub.add_parser(
        "snapshot-server-caddy",
        help="preserve a complete read-only byte prefix of the active server Caddy log",
    )
    server_snapshot.add_argument("--config")
    server_snapshot.add_argument("--purpose", choices=["readiness", "diagnostic_final"], required=True)
    server_snapshot.add_argument("--required-run-id", action="append")
    server_snapshot.add_argument("--ssh-key", default="~/.ssh/icpr_ec2")
    server_snapshot.add_argument("--approve-server-snapshot")
    server_snapshot.set_defaults(function=cmd_snapshot_server_caddy)

    validate_pf = sub.add_parser("validate-pf", help="render and non-mutatingly validate the exact PF rule")
    validate_pf.add_argument("--config")
    validate_pf.add_argument("--interface")
    validate_pf.add_argument("--system-parser", action="store_true")
    validate_pf.set_defaults(function=cmd_validate_pf)

    rehearsal = sub.add_parser(
        "rehearse-cleanup",
        help="non-counted disruptive pin/PF application and restoration rehearsal",
    )
    rehearsal.add_argument("--config")
    rehearsal.add_argument("--plan")
    rehearsal.add_argument("--approve-rehearsal")
    rehearsal.add_argument("--approve-dns")
    rehearsal.add_argument("--approve-firewall")
    rehearsal.add_argument("--approve-disruptive")
    rehearsal.set_defaults(function=cmd_rehearse_cleanup)

    prepare = sub.add_parser("prepare-run", help="start exactly one isolated diagnostic attempt")
    prepare.add_argument("--config")
    prepare.add_argument("--plan")
    prepare.add_argument("--slot-id", required=True)
    prepare.add_argument("--retry-number", type=int, required=True)
    prepare.add_argument("--condition", choices=["udp_permitted", "udp_blocked"], required=True)
    prepare.add_argument("--candidate-snapshot", required=True)
    prepare.add_argument("--real-public-ip", required=True)
    prepare.add_argument("--clock-status", choices=["synchronized", "unsynchronized"], required=True)
    prepare.add_argument("--condition-confirmation", required=True)
    prepare.add_argument("--gate-session-id")
    prepare.add_argument("--gate-ssh-key", default="~/.ssh/icpr_ec2")
    prepare.add_argument("--approve-live")
    prepare.add_argument("--approve-dns")
    prepare.add_argument("--approve-firewall")
    prepare.add_argument("--approve-disruptive")
    prepare.set_defaults(function=cmd_prepare)

    finish = sub.add_parser("finish-run", help="finish, restore, retain, and hash a diagnostic attempt")
    finish.add_argument("attempt")
    finish.add_argument("--response-file")
    finish.add_argument(
        "--outcome",
        choices=[
            "success",
            "timeout",
            "private_relay_unavailable",
            "alternative_ingress",
            "direct_bypass",
            "multiple_destination_connections",
        ],
        default="success",
    )
    finish.add_argument("--reason", default="")
    finish.add_argument("--condition-changed", action="store_true")
    finish.add_argument("--end-condition-confirmation", required=True)
    finish.set_defaults(function=cmd_finish)

    abort = sub.add_parser("abort-run", help="abort, restore, retain, and hash a diagnostic attempt")
    abort.add_argument("attempt")
    abort.add_argument("--reason", required=True)
    abort.add_argument(
        "--mechanical-failure-code",
        choices=["RESPONSE_EVIDENCE_NOT_SAVED"],
    )
    abort.add_argument("--safety-stop-code", choices=sorted(SAFETY_STOP_CODES))
    abort.add_argument("--condition-changed", action="store_true")
    abort.add_argument("--end-condition-confirmation", required=True)
    abort.set_defaults(function=cmd_abort)

    cleanup = sub.add_parser("cleanup", help="restore only this diagnostic attempt's temporary state")
    cleanup.add_argument("attempt")
    cleanup.set_defaults(function=cmd_cleanup)

    pair = sub.add_parser("pair", help="write separate diagnostic pairing/classification outputs")
    pair.add_argument("--config")
    pair.add_argument("--client-root")
    pair.add_argument("--server-root", default=str(REPO_ROOT / "server" / "recovery-data"))
    pair.add_argument("--derived-root")
    pair.set_defaults(function=cmd_pair)

    gate_validate = sub.add_parser("gate-validate", help="validate the exact server origin gate without applying it")
    gate_validate.add_argument("--config")
    gate_validate.add_argument("--session-id", required=True)
    gate_validate.add_argument("--ssh-key", default="~/.ssh/icpr_ec2")
    gate_validate.add_argument("--approve-gate-validation")
    gate_validate.set_defaults(function=cmd_gate_validate)

    gate_arm = sub.add_parser("gate-arm", help="apply the approved temporary server origin gate")
    gate_arm.add_argument("--config")
    gate_arm.add_argument("--session-id", required=True)
    gate_arm.add_argument("--ssh-key", default="~/.ssh/icpr_ec2")
    gate_arm.add_argument("--approve-origin-gate")
    gate_arm.set_defaults(function=cmd_gate_arm)

    gate_status = sub.add_parser("gate-status", help="record a validated server origin-gate snapshot")
    gate_status.add_argument("--config")
    gate_status.add_argument("--session-id", required=True)
    gate_status.add_argument("--ssh-key", default="~/.ssh/icpr_ec2")
    gate_status.set_defaults(function=cmd_gate_status)

    gate_disarm = sub.add_parser("gate-disarm", help="remove only the approved temporary server origin gate")
    gate_disarm.add_argument("--config")
    gate_disarm.add_argument("--session-id", required=True)
    gate_disarm.add_argument("--ssh-key", default="~/.ssh/icpr_ec2")
    gate_disarm.add_argument("--approve-origin-gate-removal")
    gate_disarm.set_defaults(function=cmd_gate_disarm)

    verify_controls = sub.add_parser(
        "verify-controls",
        help="freeze and validate the three required non-counted control attestations",
    )
    verify_controls.add_argument("--session-id", required=True)
    verify_controls.add_argument("--warmup-file", required=True)
    verify_controls.add_argument("--tcp-control-file", required=True)
    verify_controls.add_argument("--pre-h3-control-file", required=True)
    verify_controls.set_defaults(function=cmd_verify_controls)

    watchdog = sub.add_parser("_watchdog", help=argparse.SUPPRESS)
    watchdog.add_argument("attempt")
    watchdog.add_argument("--deadline-utc", required=True)
    watchdog.set_defaults(function=cmd_watchdog)
    return root


def main(argv: Any = None, *, default_profile: str = "dual_protocol") -> int:
    try:
        args = parser(default_profile).parse_args(argv)
        activate_series_profile(get_series_profile(args.series_profile))
        return int(args.function(args))
    except IcprError as exc:
        print(f"[icpr-protocol-diagnostic] ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[icpr-protocol-diagnostic] interrupted; run cleanup if an attempt is open", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
