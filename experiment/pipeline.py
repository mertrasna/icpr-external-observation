"""Hash-first deterministic pairing pipeline for Step 9."""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from icprlib import (
    CONFIG_PATH,
    EXPERIMENT_ROOT,
    PIPELINE_VERSION,
    REQUIRED_PAIR_FIELDS,
    IcprError,
    epoch_to_utc,
    load_json_yaml,
    longest_prefix_match,
    parse_utc,
    sha256_file,
    verify_attempt,
    verify_sidecar,
    write_csv,
    write_json,
    write_sidecar,
)
from objective_eligibility import write_objective_eligibility


PACKET_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.seq_raw",
    "tcp.len",
    "tcp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "udp.stream",
    "quic.long.packet_type",
    "quic.dcid",
    "quic.scid",
    "quic.version",
]

APPLE_FEED_FIELDS = ("ip_prefix", "country", "region", "city")


def _read_apple_feed(path: Path) -> list[dict[str, str]]:
    """Read either the native Apple export or an explicit-header fixture.

    Apple's native snapshots are headerless and currently end each row with an
    empty fifth field. The source file is never rewritten; its original hash is
    verified and preserved by the caller.
    """

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            raw_rows = [row for row in csv.reader(handle) if any(cell.strip() for cell in row)]
    except (OSError, UnicodeError, csv.Error) as exc:
        raise IcprError(f"unable to read Apple feed {path}: {exc}") from exc
    if not raw_rows:
        raise IcprError(f"Apple feed contains no rows: {path}")

    first = [cell.lstrip("\ufeff").strip() for cell in raw_rows[0]]
    first_lower = [cell.lower() for cell in first]
    required = set(APPLE_FEED_FIELDS)
    if required.issubset(first_lower):
        if len(first_lower) != len(set(first_lower)):
            raise IcprError(f"Apple feed contains duplicate header names: {path}")
        indexes = {field: first_lower.index(field) for field in APPLE_FEED_FIELDS}
        data_rows = raw_rows[1:]
        rows = [
            {field: row[indexes[field]] if indexes[field] < len(row) else "" for field in APPLE_FEED_FIELDS}
            for row in data_rows
        ]
    else:
        rows = []
        for line_number, row in enumerate(raw_rows, 1):
            if len(row) < 4:
                raise IcprError(
                    f"native Apple feed row has fewer than four fields at {path}:{line_number}"
                )
            if any(cell.strip() for cell in row[4:]):
                raise IcprError(
                    f"native Apple feed row has an unexpected nonempty trailing field "
                    f"at {path}:{line_number}"
                )
            rows.append(dict(zip(APPLE_FEED_FIELDS, row[:4], strict=True)))
    if not rows:
        raise IcprError(f"Apple feed contains no data rows: {path}")
    return rows


def _integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        try:
            return int(float(str(value)))
        except ValueError:
            return None


def _number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}


def _normalized_location_value(value: Any) -> str:
    """Normalize only for comparison; raw Apple values remain in output records."""

    return str(value or "").strip().casefold()


def _parse_response_server_utc(value: Any) -> dt.datetime:
    """Parse the endpoint's UTC timestamp without trusting its monotonic suffix.

    Caddy's ``{time.now}`` placeholder uses Go's time representation, for example
    ``2006-01-02 15:04:05.11906749 +0000 UTC m=+12345.6789``.  The
    monotonic component is process-local, so it is deliberately ignored; the
    wall-clock value is still cross-checked against both ``server_unix_ms`` and
    the selected Caddy record later in pairing.
    """

    text = str(value or "").strip()
    try:
        return parse_utc(text)
    except IcprError as iso_error:
        match = re.fullmatch(
            r"(?P<base>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"(?:\.(?P<fraction>\d{1,9}))? \+0000 UTC"
            r"(?: m=[+-]\d+(?:\.\d+)?)?",
            text,
        )
        if not match:
            raise iso_error
        parsed = dt.datetime.strptime(
            match.group("base"), "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=dt.timezone.utc)
        fraction = match.group("fraction") or ""
        return parsed.replace(microsecond=int((fraction + "000000")[:6]))


def _quic_initial(raw: dict[str, Any]) -> bool:
    """Return true only for an explicit fixture boolean or QUIC long-header type 0."""
    fixture_value = raw.get("quic_initial")
    if isinstance(fixture_value, bool):
        return fixture_value
    if isinstance(fixture_value, str) and fixture_value.lower() in {"true", "false"}:
        return fixture_value.lower() == "true"
    # Wireshark's quic.long.packet_type enum is 0=Initial, 1=0-RTT,
    # 2=Handshake and 3=Retry. In particular, numeric 1 is not truthy here.
    return str(raw.get("quic.long.packet_type", "")) == "0"


def normalize_packet(raw: dict[str, Any], source: str, artifact_hash: str) -> dict[str, Any]:
    def first(*keys: str) -> Any:
        for key in keys:
            if raw.get(key) not in (None, ""):
                return raw[key]
        return None

    tcp_source = _integer(first("tcp_srcport", "tcp.srcport"))
    tcp_destination = _integer(first("tcp_dstport", "tcp.dstport"))
    udp_source = _integer(first("udp_srcport", "udp.srcport"))
    udp_destination = _integer(first("udp_dstport", "udp.dstport"))
    transport = raw.get("transport")
    if not transport:
        if tcp_source is not None or tcp_destination is not None:
            transport = "tcp"
        elif udp_source is not None or udp_destination is not None:
            transport = "udp"
    if transport == "tcp":
        tcp_source = tcp_source if tcp_source is not None else _integer(raw.get("src_port"))
        tcp_destination = (
            tcp_destination if tcp_destination is not None else _integer(raw.get("dst_port"))
        )
    elif transport == "udp":
        udp_source = udp_source if udp_source is not None else _integer(raw.get("src_port"))
        udp_destination = (
            udp_destination if udp_destination is not None else _integer(raw.get("dst_port"))
        )
    return {
        "frame_number": _integer(first("frame_number", "frame.number")),
        "time_epoch": _number(first("time_epoch", "frame.time_epoch")),
        "src_ip": first("src_ip", "ip.src", "ipv6.src"),
        "dst_ip": first("dst_ip", "ip.dst", "ipv6.dst"),
        "transport": transport,
        "src_port": tcp_source if transport == "tcp" else udp_source,
        "dst_port": tcp_destination if transport == "tcp" else udp_destination,
        "tcp_syn": _flag(first("tcp_syn", "tcp.flags.syn")),
        "tcp_ack": _flag(first("tcp_ack", "tcp.flags.ack")),
        "tcp_seq_raw": _integer(first("tcp_seq_raw", "tcp.seq_raw")),
        "tcp_len": _integer(first("tcp_len", "tcp.len")) or 0,
        "udp_length": _integer(first("udp_length", "udp.length")) or 0,
        "stream": first(
            "stream",
            "tcp.stream" if transport == "tcp" else "udp.stream",
        ),
        "quic_initial": _quic_initial(raw),
        "quic_dcid": first("quic_dcid", "quic.dcid"),
        "quic_scid": first("quic_scid", "quic.scid"),
        "quic_version": first("quic_version", "quic.version"),
        "artifact": source,
        "artifact_sha256": artifact_hash,
    }


def tshark_packets(path: Path, artifact_hash: str) -> list[dict[str, Any]]:
    argv = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in PACKET_FIELDS:
        argv.extend(["-e", field])
    result = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise IcprError(f"tshark failed for {path}: {result.stderr.strip()}")
    rows = csv.DictReader(result.stdout.splitlines(), delimiter="\t", quotechar='"')
    return [normalize_packet(dict(row), str(path), artifact_hash) for row in rows]


def jsonl_packets(path: Path, artifact_hash: str) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IcprError(f"invalid packet fixture {path}:{line_number}: {exc}") from exc
        if not isinstance(raw, dict):
            raise IcprError(f"packet fixture must contain JSON objects: {path}:{line_number}")
        packets.append(normalize_packet(raw, str(path), artifact_hash))
    return packets


def load_packet_tree(root: Path, *, manifest_verified: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
    packets: list[dict[str, Any]] = []
    errors: list[str] = []
    candidates = sorted(
        list(root.rglob("*.pcap"))
        + list(root.rglob("*.pcapng"))
        + list(root.rglob("*.packets.jsonl"))
    )
    for path in candidates:
        try:
            artifact_hash = sha256_file(path) if manifest_verified else verify_sidecar(path)
            if path.name.endswith(".packets.jsonl"):
                packets.extend(jsonl_packets(path, artifact_hash))
            else:
                packets.extend(tshark_packets(path, artifact_hash))
        except (IcprError, OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    return packets, errors


def load_caddy_tree(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_rows: set[str] = set()
    files = sorted(list(root.rglob("*.jsonl")) + list(root.rglob("*.jsonl.gz")))
    files = [path for path in files if not path.name.endswith(".packets.jsonl")]
    for path in files:
        try:
            artifact_hash = verify_sidecar(path)
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    row_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    if row_hash in seen_rows:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise IcprError(f"invalid Caddy JSON {path}:{line_number}: {exc}") from exc
                    if not isinstance(row, dict):
                        raise IcprError(f"Caddy JSON must contain objects: {path}:{line_number}")
                    seen_rows.add(row_hash)
                    row["_artifact"] = str(path)
                    row["_artifact_sha256"] = artifact_hash
                    row["_line_number"] = line_number
                    row["_row_sha256"] = row_hash
                    records.append(row)
        except (IcprError, OSError) as exc:
            errors.append(str(exc))
    return records, errors


def _attempt_times(
    attempt_dir: Path, metadata: dict[str, Any]
) -> tuple[str | None, str | None, str | None, str | None, dict[str, Any] | None]:
    started = metadata.get("client_start_utc")
    finished = None
    safari_launch = metadata.get("safari_launch_requested_utc")
    capture_stopped = None
    finished_event = None
    lifecycle_seen: set[str] = set()
    events = attempt_dir / "events.jsonl"
    if events.is_file():
        for line_number, line in enumerate(events.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IcprError(f"invalid attempt event JSON {events}:{line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise IcprError(f"attempt event must be a JSON object: {events}:{line_number}")
            event_name = event.get("event")
            if event_name in {
                "run_started",
                "safari_url_launch_requested",
                "capture_stopped",
                "run_finished",
            }:
                if event_name in lifecycle_seen:
                    raise IcprError(f"duplicate lifecycle event {event_name!r}: {events}")
                lifecycle_seen.add(event_name)
            if event_name == "run_started":
                started = event.get("recorded_utc", started)
            elif event_name == "safari_url_launch_requested":
                safari_launch = event.get("recorded_utc")
            elif event_name == "capture_stopped":
                capture_stopped = event.get("recorded_utc")
            elif event_name == "run_finished":
                finished = event.get("recorded_utc")
                finished_event = event
    return started, safari_launch, capture_stopped, finished, finished_event


def _base_record(
    metadata: dict[str, Any], attempt_dir: Path, *, read_events: bool = True
) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise IcprError(f"attempt metadata must be a JSON object: {attempt_dir / 'metadata.json'}")
    if read_events:
        started, safari_launch, capture_stopped, finished, finished_event = _attempt_times(
            attempt_dir, metadata
        )
    else:
        started = metadata.get("client_start_utc")
        safari_launch = metadata.get("safari_launch_requested_utc")
        capture_stopped = finished = None
        finished_event = None
    return {
        "run_id": metadata.get("run_id", attempt_dir.name),
        "campaign": metadata.get("campaign", ""),
        "run_mode": metadata.get("run_mode", ""),
        "session": metadata.get("session", ""),
        "slot_id": metadata.get("slot_id", ""),
        "retry_number": metadata.get("retry_number", ""),
        "block_id": metadata.get("block_id", ""),
        "attempt_number": metadata.get("attempt_number", ""),
        "client_start_utc": started or "",
        "client_end_utc": finished or "",
        "safari_launch_utc": safari_launch or "",
        "capture_stopped_utc": capture_stopped or "",
        "server_time_utc": "",
        "client_ingress_attribution_end_utc": "",
        "clock_status": metadata.get("clock_status", ""),
        "private_relay_state": metadata.get("private_relay_state", ""),
        "location_setting": metadata.get("location_setting", ""),
        "intended_ingress_group": metadata.get("intended_ingress_group", ""),
        "intended_ingress_ip": metadata.get("intended_ingress_ip") or "",
        "pin_contact_status": "not_applicable",
        "fresh_pin_contact_status": "not_applicable",
        "ingress_attribution_policy": metadata.get(
            "ingress_attribution_policy", "bounded_candidate_contact_v2"
        ),
        "observed_ingress_ip": "",
        "ingress_transport": "",
        "ingress_5tuple": "",
        "freshness_evidence": "",
        "server_remote_ip": "",
        "server_remote_port": "",
        "server_transport": "",
        "server_http_protocol": "",
        "server_flow_key": "",
        "server_delivery_count": 0,
        "server_delivery_sequence": [],
        "response_status": "",
        "apple_feed_date": "",
        "apple_feed_hash": "",
        "matched_prefix": "",
        "advertised_country": "",
        "advertised_region": "",
        "advertised_city": "",
        "ingress_asn": "",
        "egress_asn": "",
        "ingress_operator": "",
        "egress_operator": "",
        "operator_map_version": "",
        "same_operator": "",
        "disclosure_class": "",
        "disposition": "pending",
        "exclusion_reason": "",
        "pipeline_version": PIPELINE_VERSION,
        "controller_version": metadata.get("controller_version", ""),
        "config_version": metadata.get("config_version", ""),
        "config_sha256": metadata.get("config_sha256", ""),
        "execution_plan_version": metadata.get("execution_plan_version", ""),
        "execution_plan_sha256": metadata.get("execution_plan_sha256", ""),
        "pin_list_version": metadata.get("pin_list_version", ""),
        "pin_list_sha256": metadata.get("pin_list_sha256", ""),
        "approved_ingress_candidates": metadata.get("approved_ingress_candidates", []),
        "approved_pin_group_addresses": metadata.get("approved_pin_group_addresses", []),
        "capture_recent_candidates": metadata.get("capture_recent_candidates", []),
        "capture_recent_candidate_provenance": metadata.get(
            "capture_recent_candidate_provenance", []
        ),
        "capture_recent_candidate_policy": metadata.get(
            "capture_recent_candidate_policy", ""
        ),
        "capture_candidate_scope": metadata.get("capture_candidate_scope", ""),
        "effective_dns": metadata.get("effective_dns", {}),
        "capture_filter": metadata.get("capture_filter", ""),
        "quic_block_state": metadata.get("quic_block_state", ""),
        "fallback_pf_evidence": {},
        "timeout_deadline_utc": metadata.get("timeout_deadline_utc", ""),
        "freshness_method": metadata.get("freshness_method", ""),
        "network_type": metadata.get("network_type", ""),
        "active_interface": metadata.get("active_interface", ""),
        "macos_version": metadata.get("macos_version", ""),
        "safari_version": metadata.get("safari_version", ""),
        "real_public_ipv4": metadata.get("real_public_ipv4", ""),
        "attempt_path": str(attempt_dir),
        "validation_flags": [],
        "condition_changed": bool((finished_event or {}).get("condition_changed")),
        "client_outcome": (finished_event or {}).get("outcome", ""),
        "end_condition_confirmation": (finished_event or {}).get(
            "end_condition_confirmation", ""
        ),
    }


def _corrupt_attempt_record(
    attempt_dir: Path, reason: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    safe_metadata = metadata if isinstance(metadata, dict) else {"run_id": attempt_dir.name}
    record = _base_record(safe_metadata, attempt_dir, read_events=False)
    record["validation_flags"] = [reason]
    record["triggered_exclusions"] = ["E07_CLOCK_OR_LOG_CORRUPTION"]
    record["disposition"] = "excluded"
    record["exclusion_reason"] = "E07_CLOCK_OR_LOG_CORRUPTION"
    record["protocol_classification"] = _protocol(record)
    record["protocol_classification_basis"] = _protocol_basis(record)
    return record


def _protocol(record: dict[str, Any]) -> str:
    if (
        record.get("private_relay_state") == "off_control"
        and record.get("exclusion_reason") == "E05_REAL_IP_AT_DESTINATION"
    ):
        if (
            record.get("server_http_protocol", "").startswith("HTTP/3")
            and record.get("server_transport") == "udp"
        ):
            return "direct_http3_control"
        if record.get("server_transport") == "tcp":
            return "direct_tcp_control"
        return "ambiguous"
    if record.get("exclusion_reason") == "E05_REAL_IP_AT_DESTINATION":
        return "real_ip_bypass"
    if record.get("exclusion_reason") == "E01_NO_SERVER_OBSERVATION":
        return "dropped_or_timeout"
    if record.get("exclusion_reason") == "E02_MULTIPLE_SERVER_CONNECTIONS":
        sequence = record.get("server_delivery_sequence") or []
        transports = [item.get("transport") for item in sequence]
        if "udp" in transports and "tcp" in transports:
            if transports.index("udp") < transports.index("tcp"):
                return "mixed_http3_then_tcp_delivery"
            return "mixed_tcp_then_http3_delivery"
        return "ambiguous"
    if record.get("exclusion_reason") in {
        "E03_NO_FRESH_FLOW",
        "E04_WRONG_OR_UNKNOWN_INGRESS",
        "E07_CLOCK_OR_LOG_CORRUPTION",
        "E08_CONDITION_CHANGED",
    }:
        return "ambiguous"
    if record.get("disposition") == "pending":
        return "pending"
    if (
        record.get("server_http_protocol", "").startswith("HTTP/3")
        and record.get("server_transport") == "udp"
    ):
        return "http3_preserved"
    if record.get("server_transport") == "tcp":
        return "tcp_downgrade"
    return "ambiguous"


def _protocol_basis(record: dict[str, Any]) -> str:
    classification = record.get("protocol_classification") or _protocol(record)
    if classification == "direct_http3_control":
        return "relay-off Safari control reached the destination over fresh QUIC with the expected real IP"
    if classification == "direct_tcp_control":
        return "relay-off Safari control reached the destination over fresh TCP with the expected real IP"
    if classification == "http3_preserved":
        return "relay-on destination request used HTTP/3 over a matching fresh server-side QUIC flow"
    if classification == "tcp_downgrade":
        return "relay-on destination request used TCP; downgrade attribution requires the matched Safari HTTP/3 capability control"
    if classification == "mixed_http3_then_tcp_delivery":
        return "one tagged Safari launch produced attributable HTTP/3 then TCP deliveries; retained as an E02 protocol outcome"
    if classification == "mixed_tcp_then_http3_delivery":
        return "one tagged Safari launch produced attributable TCP then HTTP/3 deliveries; retained as an E02 protocol outcome"
    if classification == "real_ip_bypass":
        return "relay-on destination source matched the recorded real client IPv4"
    if classification == "dropped_or_timeout":
        return "no attributable destination observation was found before the response deadline"
    if classification == "pending":
        return "required contemporaneous mapping or server evidence is pending"
    return "evidence is insufficient or ambiguous under the declared exclusion rules"


def _temporal_intersection(
    declaration: Any, unpinned_sequence: list[dict[str, Any]]
) -> dict[str, Any]:
    """Evaluate only an explicitly structured exact-field intersection rule."""
    base: dict[str, Any] = {
        "declaration": declaration,
        "observations_considered": 0,
        "run_ids": [],
        "result": None,
    }
    if not declaration:
        return {**base, "status": "blocked_rule_not_declared"}
    if isinstance(declaration, str):
        return {
            **base,
            "status": "manual_evaluation_required_for_free_text_rule",
        }
    if not isinstance(declaration, dict):
        return {**base, "status": "invalid_rule_declaration"}
    rule_id = declaration.get("rule_id")
    if rule_id not in {"exact_value_intersection", "exact_advertised_field_intersection"}:
        return {**base, "status": "unsupported_rule_id"}
    if declaration.get("comparison_normalization") != "trim_casefold_preserve_raw":
        return {**base, "status": "unsupported_comparison_normalization"}
    fields = declaration.get("fields")
    aliases = {
        "country": "advertised_country",
        "region": "advertised_region",
        "city": "advertised_city",
        "advertised_country": "advertised_country",
        "advertised_region": "advertised_region",
        "advertised_city": "advertised_city",
    }
    if (
        not isinstance(fields, list)
        or not fields
        or any(field not in aliases for field in fields)
        or len(set(fields)) != len(fields)
    ):
        return {**base, "status": "invalid_or_unsupported_fields"}
    accepted = [
        row
        for row in unpinned_sequence
        if row.get("disposition") == "accepted"
    ]
    base["observations_considered"] = len(accepted)
    base["run_ids"] = [row.get("run_id", "") for row in accepted]
    if not accepted:
        return {**base, "status": "insufficient_accepted_unpinned_observations"}
    result: dict[str, list[str]] = {}
    observed_raw_values: dict[str, list[str]] = {}
    for declared_field in fields:
        record_field = aliases[declared_field]
        raw_values = [str(row.get(record_field) or "") for row in accepted]
        values = [_normalized_location_value(value) for value in raw_values]
        observed_raw_values[declared_field] = sorted(set(raw_values))
        if any(not value for value in values):
            return {**base, "status": "incomplete_location_fields"}
        intersection = set(values[:1])
        for value in values[1:]:
            intersection.intersection_update({value})
        result[declared_field] = sorted(intersection)
    return {
        **base,
        "status": "evaluated",
        "result": result,
        "observed_raw_values": observed_raw_values,
        "all_declared_fields_have_nonempty_intersection": all(result.values()),
    }


def _load_operator_map(
    path: Path, mapping: dict[str, Any]
) -> tuple[list[dict[str, str]], dict[str, dict[str, str]], str, set[str]]:
    """Load a hash-verified, version-consistent operator map."""
    digest = verify_sidecar(path)
    expected_fields = {"asn", "operator_id", "operator_name", "mapping_rule", "version"}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        if not expected_fields.issubset(fieldnames):
            missing = sorted(expected_fields - fieldnames)
            raise IcprError(f"operator map is missing required columns {missing}: {path}")
        rows = list(reader)
    if not rows:
        raise IcprError(f"operator map contains no rows: {path}")
    expected_version = str(mapping.get("operator_map_version") or "")
    if not expected_version:
        raise IcprError("mapping.operator_map_version is required")
    by_asn: dict[str, dict[str, str]] = {}
    for line_number, row in enumerate(rows, 2):
        try:
            asn_number = int(str(row.get("asn", "")))
        except ValueError as exc:
            raise IcprError(f"invalid operator-map ASN at {path}:{line_number}") from exc
        if not 1 <= asn_number <= 4_294_967_295:
            raise IcprError(f"operator-map ASN is outside the valid range at {path}:{line_number}")
        asn = str(asn_number)
        if asn in by_asn:
            raise IcprError(f"duplicate operator-map ASN {asn}: {path}")
        if row.get("version") != expected_version:
            raise IcprError(
                f"operator-map row version {row.get('version')!r} does not equal "
                f"configured version {expected_version!r}: {path}:{line_number}"
            )
        for field in ("operator_id", "operator_name", "mapping_rule"):
            if not str(row.get(field, "")).strip():
                raise IcprError(f"empty operator-map {field}: {path}:{line_number}")
        normalized = {key: str(value or "") for key, value in row.items()}
        normalized["asn"] = asn
        by_asn[asn] = normalized

    if "714" not in by_asn:
        raise IcprError("operator map must contain the explicit Apple AS714 mapping")
    if by_asn["714"]["operator_id"] != "apple":
        raise IcprError("operator map must assign operator_id='apple' to AS714")

    sibling_values = mapping.get("akamai_sibling_asns") or []
    if not isinstance(sibling_values, list):
        raise IcprError("mapping.akamai_sibling_asns must be a list")
    try:
        sibling_asns = {str(int(value)) for value in sibling_values}
    except (TypeError, ValueError) as exc:
        raise IcprError("mapping.akamai_sibling_asns must contain integer ASNs") from exc
    if len(sibling_asns) != len(sibling_values):
        raise IcprError("mapping.akamai_sibling_asns contains duplicates")
    missing_siblings = sorted(sibling_asns - set(by_asn), key=int)
    if missing_siblings:
        raise IcprError(
            f"Akamai sibling ASNs are absent from the operator map: {missing_siblings}"
        )
    sibling_operators = {by_asn[asn]["operator_id"] for asn in sibling_asns}
    if len(sibling_operators) > 1:
        raise IcprError(
            "all frozen Akamai sibling ASNs must map to one canonical operator_id"
        )
    if sibling_operators and by_asn["714"]["operator_id"] in sibling_operators:
        raise IcprError(
            "Apple AS714 and the frozen Akamai sibling group must not share an operator_id"
        )
    return list(by_asn.values()), by_asn, digest, sibling_asns


def _load_asn_rows(path: Path) -> tuple[list[dict[str, str]], str]:
    digest = verify_sidecar(path)
    required_fields = {"date", "prefix", "asn", "source", "source_hash"}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        if not required_fields.issubset(fields):
            raise IcprError(
                f"dated ASN file is missing required columns "
                f"{sorted(required_fields - fields)}: {path}"
            )
        raw_rows = list(reader)
    if not raw_rows:
        raise IcprError(f"dated ASN file contains no rows: {path}")
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for line_number, row in enumerate(raw_rows, 2):
        try:
            date = dt.date.fromisoformat(str(row.get("date", ""))).isoformat()
            prefix = str(ipaddress.ip_network(str(row.get("prefix", "")), strict=False))
            asn_number = int(str(row.get("asn", "")))
            if not 1 <= asn_number <= 4_294_967_295:
                raise ValueError("ASN is outside the valid range")
        except (ValueError, TypeError) as exc:
            raise IcprError(f"invalid dated ASN row at {path}:{line_number}: {exc}") from exc
        source_hash = str(row.get("source_hash", "")).strip().lower()
        if not str(row.get("source", "")).strip() or not re.fullmatch(
            r"[0-9a-f]{64}", source_hash
        ):
            raise IcprError(f"dated ASN row lacks source provenance at {path}:{line_number}")
        identity = (date, prefix, str(asn_number))
        if identity in seen:
            raise IcprError(f"duplicate dated ASN row {identity}: {path}")
        seen.add(identity)
        normalized = {key: str(value or "") for key, value in row.items()}
        normalized.update(
            date=date,
            prefix=prefix,
            asn=str(asn_number),
            source_hash=source_hash,
        )
        rows.append(normalized)
    return rows, digest


class PairingPipeline:
    def __init__(
        self,
        *,
        experiment_root: Path = EXPERIMENT_ROOT,
        config_path: Path = CONFIG_PATH,
        client_root: Path | None = None,
        server_root: Path | None = None,
        feed_root: Path | None = None,
        asn_path: Path | None = None,
        operator_map_path: Path | None = None,
    ) -> None:
        self.root = experiment_root
        self.config = load_json_yaml(config_path)
        self.client_root = client_root or self.root / "client"
        self.server_root = server_root or self.root / "server"
        self.feed_root = feed_root or self.root / "feeds" / "apple"
        mapping = self.config["mapping"]
        self.asn_path = asn_path or self.root / mapping["origin_asn_file"]
        self.operator_map_path = operator_map_path or self.root / mapping["operator_map_file"]
        self.caddy_records, self.server_log_errors = load_caddy_tree(self.server_root)
        self.server_packets, self.server_packet_errors = load_packet_tree(self.server_root)
        server_errors = self.server_log_errors + self.server_packet_errors
        if server_errors:
            raise IcprError(
                "server archive integrity verification failed; refusing partial pairing: "
                + "; ".join(server_errors)
            )
        (
            self.operator_rows,
            self.operator_by_asn,
            self.operator_map_hash,
            self.akamai_sibling_asns,
        ) = _load_operator_map(self.operator_map_path, mapping)
        self.asn_rows: list[dict[str, str]] = []
        self.asn_error: str | None = None
        self.asn_hash = ""
        if self.asn_path.is_file():
            try:
                self.asn_rows, self.asn_hash = _load_asn_rows(self.asn_path)
            except (IcprError, OSError) as exc:
                self.asn_error = str(exc)

    def _attempt_dirs(self) -> list[Path]:
        return sorted({path.parent for path in self.client_root.rglob("metadata.json")})

    def _exact_caddy(self, run_id: str) -> list[dict[str, Any]]:
        expected_uri = f"/probe/{run_id}"
        hostname = self.config["server"]["hostname"]
        results = []
        for row in self.caddy_records:
            request = row.get("request")
            if not isinstance(request, dict):
                continue
            host = str(request.get("host", "")).split(":", 1)[0]
            if (
                row.get("run_id") == run_id
                and request.get("uri") == expected_uri
                and host == hostname
                and request.get("method") == "GET"
            ):
                results.append(row)
        return results

    def _caddy_schema_errors(self, run_id: str) -> list[str]:
        errors: list[str] = []
        expected_uri = f"/probe/{run_id}"
        hostname = self.config["server"]["hostname"]
        for row in self.caddy_records:
            if row.get("run_id") != run_id:
                continue
            location = f"{row.get('_artifact', 'unknown')}:{row.get('_line_number', '?')}"
            request = row.get("request")
            if not isinstance(request, dict):
                errors.append(f"Caddy request is not an object at {location}")
                continue
            required = ("remote_ip", "remote_port", "proto", "method", "host", "uri")
            missing = [key for key in required if request.get(key) in (None, "")]
            if missing:
                errors.append(f"Caddy request is missing {missing} at {location}")
                continue
            try:
                ipaddress.IPv4Address(str(request["remote_ip"]))
                remote_port = int(str(request["remote_port"]))
                if not 1 <= remote_port <= 65535:
                    raise ValueError("remote port is outside 1..65535")
                timestamp = float(row["ts"])
                dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)
                int(row["status"])
            except (KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
                errors.append(f"invalid Caddy probe schema at {location}: {exc}")
                continue
            host = str(request["host"]).split(":", 1)[0]
            if (
                request["method"] != "GET"
                or request["uri"] != expected_uri
                or host != hostname
                or not str(request["proto"]).startswith("HTTP/")
                or not row.get("request_uuid")
            ):
                errors.append(f"Caddy probe identity/schema mismatch at {location}")
        return errors

    @staticmethod
    def _server_flow(row: dict[str, Any], private_ip: str) -> tuple[str, str]:
        request = row.get("request")
        if not isinstance(request, dict):
            raise IcprError("Caddy request is not an object")
        proto = str(request.get("proto", ""))
        if not proto.startswith("HTTP/"):
            raise IcprError(f"invalid Caddy HTTP protocol: {proto!r}")
        transport = "udp" if proto.startswith("HTTP/3") else "tcp"
        remote_ip = str(ipaddress.IPv4Address(str(request.get("remote_ip", ""))))
        private_ip = str(ipaddress.IPv4Address(private_ip))
        remote_port = int(str(request.get("remote_port", "0")))
        if not 1 <= remote_port <= 65535:
            raise IcprError(f"invalid Caddy remote port: {remote_port}")
        return transport, f"{transport}|{remote_ip}|{remote_port}|{private_ip}|443"

    def _freshness(
        self,
        *,
        row: dict[str, Any],
        start: dt.datetime,
        end: dt.datetime,
        private_ip: str,
    ) -> tuple[dict[str, Any] | None, bool]:
        request = row["request"]
        remote_ip = str(ipaddress.IPv4Address(str(request["remote_ip"])))
        private_ip = str(ipaddress.IPv4Address(private_ip))
        remote_port = int(str(request["remote_port"]))
        transport, _ = self._server_flow(row, private_ip)
        log_epoch = float(row["ts"])
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        for packet in self.server_packets:
            timestamp = packet.get("time_epoch")
            if timestamp is None:
                continue
            if timestamp > log_epoch:
                continue
            if (
                packet.get("src_ip") == remote_ip
                and packet.get("dst_ip") == private_ip
                and packet.get("src_port") == remote_port
                and packet.get("dst_port") == 443
                and packet.get("transport") == transport
            ):
                if transport == "tcp" and packet.get("tcp_syn") and not packet.get("tcp_ack"):
                    sequence = packet.get("tcp_seq_raw")
                    stream = packet.get("stream")
                    if sequence is not None:
                        identity = ("tcp-sequence", str(sequence))
                    elif stream not in (None, ""):
                        identity = (
                            "tcp-stream",
                            str(packet.get("artifact_sha256", "")),
                            str(stream),
                        )
                    else:
                        identity = ("tcp-five-tuple",)
                    groups[identity].append(packet)
                elif transport == "udp" and packet.get("quic_initial") and packet.get("quic_dcid"):
                    # A normal QUIC handshake can change DCID after the server's
                    # first Initial. The selected Caddy 5-tuple remains the
                    # attributable flow, so preserve every observed Initial DCID
                    # without treating that evolution as a second connection.
                    groups[("quic-five-tuple",)].append(packet)
        if not groups:
            return None, False

        in_window: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for identity, packets in groups.items():
            candidates = []
            for packet in packets:
                try:
                    packet_time = dt.datetime.fromtimestamp(
                        float(packet["time_epoch"]), tz=dt.timezone.utc
                    )
                except (KeyError, TypeError, ValueError, OverflowError, OSError):
                    continue
                if start <= packet_time <= end:
                    candidates.append(packet)
            if candidates:
                in_window[identity] = packets
        if not in_window:
            return None, False
        if len(in_window) != 1:
            return None, True

        identity, packets = next(iter(in_window.items()))
        packets.sort(key=lambda item: item["time_epoch"])
        first = packets[0]
        first_time = dt.datetime.fromtimestamp(float(first["time_epoch"]), tz=dt.timezone.utc)
        # A SYN/Initial first observed before Safari launch is a retransmission or an
        # already-started connection, not a newly established measurement unit.
        if first_time < start:
            return None, False

        if transport == "tcp":
            return {
                "kind": "tcp_syn",
                "frame_numbers": [item["frame_number"] for item in packets],
                "first_epoch": first["time_epoch"],
                "connection_identity": list(identity),
                "five_tuple": f"tcp|{remote_ip}|{remote_port}|{private_ip}|443",
                "pcap_sha256": first["artifact_sha256"],
                "pcap_path": first["artifact"],
            }, False
        dcids = list(
            dict.fromkeys(
                str(item["quic_dcid"]).replace(":", "").lower()
                for item in packets
                if item.get("quic_dcid")
            )
        )
        return {
            "kind": "quic_initial",
            "initial_dcid": dcids[0],
            "initial_dcids": dcids,
            "frame_numbers": [item["frame_number"] for item in packets],
            "first_epoch": first["time_epoch"],
            "connection_identity": list(identity),
            "five_tuple": f"udp|{remote_ip}|{remote_port}|{private_ip}|443",
            "pcap_sha256": first["artifact_sha256"],
            "pcap_path": first["artifact"],
        }, False

    @staticmethod
    def _client_ingress(
        metadata: dict[str, Any],
        packets: list[dict[str, Any]],
        start: dt.datetime,
        end: dt.datetime,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Separate general candidate contact from new-handshake evidence.

        General contacts remain useful for diagnosing whether the intended pin
        was ever contacted. Ingress attribution, however, uses only a client TCP
        SYN (without ACK) or a QUIC Initial. Established/background payload must
        not make a fresh connection ambiguous.
        """

        candidates: set[str] = set()
        for value in metadata.get("approved_ingress_candidates") or []:
            try:
                candidates.add(str(ipaddress.IPv4Address(value)))
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise IcprError(f"invalid approved ingress candidate: {value!r}") from exc
        intended = metadata.get("intended_ingress_ip")
        if intended:
            try:
                candidates.add(str(ipaddress.IPv4Address(intended)))
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise IcprError(f"invalid intended ingress IPv4 address: {intended!r}") from exc
        contacts: dict[tuple[str, str, int, str, int], dict[str, Any]] = {}
        fresh_contacts: dict[
            tuple[str, str, int, str, int], dict[str, Any]
        ] = {}
        for packet in packets:
            packet_epoch = packet.get("time_epoch")
            if packet_epoch is None:
                continue
            packet_time = dt.datetime.fromtimestamp(packet_epoch, tz=dt.timezone.utc)
            if not start <= packet_time <= end:
                continue
            if packet.get("dst_ip") not in candidates or packet.get("dst_port") != 443:
                continue
            transport = packet.get("transport")
            contacted = (
                transport == "tcp"
                and (packet.get("tcp_syn") or int(packet.get("tcp_len") or 0) > 0)
            ) or (transport == "udp" and int(packet.get("udp_length") or 0) > 8)
            if not contacted:
                continue
            key = (
                transport,
                str(packet.get("src_ip") or ""),
                int(packet.get("src_port") or 0),
                str(packet["dst_ip"]),
                443,
            )
            contacts.setdefault(key, packet)
            fresh = (
                transport == "tcp"
                and packet.get("tcp_syn")
                and not packet.get("tcp_ack")
            ) or (transport == "udp" and packet.get("quic_initial"))
            if fresh:
                fresh_contacts.setdefault(key, packet)

        def materialize(
            values: dict[tuple[str, str, int, str, int], dict[str, Any]],
        ) -> list[dict[str, Any]]:
            return [
                {
                    "transport": key[0],
                    "five_tuple": "|".join(map(str, key)),
                    "ingress_ip": key[3],
                    "artifact_sha256": value["artifact_sha256"],
                    "artifact": value["artifact"],
                    "frame_number": value["frame_number"],
                    "time_epoch": value["time_epoch"],
                }
                for key, value in sorted(values.items())
            ]

        return materialize(contacts), materialize(fresh_contacts)

    @staticmethod
    def _bounded_attribution_candidate_ips(metadata: dict[str, Any]) -> set[str]:
        """Return candidates directly justified for this attempt.

        The capture filter may be wider so that a persistent tunnel is not
        missed.  That wider observability scope is not attribution evidence.
        Pinned runs therefore use only the intended pin; unpinned runs use only
        resolver answers recorded by the current attempt.  The old expanded
        union is used only as a compatibility fallback when no direct source
        exists in very early records.
        """

        def normalized(values: Any) -> set[str]:
            result: set[str] = set()
            if not isinstance(values, (list, tuple, set)):
                return result
            for value in values:
                try:
                    result.add(str(ipaddress.IPv4Address(value)))
                except (ipaddress.AddressValueError, TypeError):
                    continue
            return result

        intended = metadata.get("intended_ingress_ip")
        if intended:
            try:
                return {str(ipaddress.IPv4Address(intended))}
            except (ipaddress.AddressValueError, TypeError) as exc:
                raise IcprError(
                    f"invalid intended ingress IPv4 address: {intended!r}"
                ) from exc

        candidates = normalized(metadata.get("dns_ingress_candidates"))
        candidates.update(
            normalized(metadata.get("macos_effective_ingress_candidates"))
        )
        effective_dns = metadata.get("effective_dns")
        if isinstance(effective_dns, dict):
            hostnames = effective_dns.get("hostnames")
            if isinstance(hostnames, dict):
                for records in hostnames.values():
                    if not isinstance(records, dict):
                        continue
                    answers = records.get("A")
                    if not isinstance(answers, list):
                        continue
                    for answer in answers:
                        if not isinstance(answer, dict):
                            continue
                        try:
                            candidates.add(
                                str(ipaddress.IPv4Address(answer.get("address")))
                            )
                        except (ipaddress.AddressValueError, TypeError):
                            continue
        if candidates:
            return candidates
        return normalized(metadata.get("approved_ingress_candidates"))

    @staticmethod
    def _pin_contact_status(intended_ip: str, contacts: list[dict[str, Any]]) -> str:
        if not intended_ip:
            return "not_applicable"
        contacted_ips = {contact["ingress_ip"] for contact in contacts}
        if contacted_ips == {intended_ip}:
            return "intended_ingress_observed"
        if intended_ip in contacted_ips:
            return "intended_and_other_ingresses_observed"
        if contacted_ips:
            return "other_ingress_observed"
        return "intended_ingress_not_observed"

    @staticmethod
    def _mask_h2_queries(
        attempt_dir: Path, start: dt.datetime, end: dt.datetime
    ) -> list[dict[str, Any]]:
        query_log = attempt_dir / "dns-queries.jsonl"
        if not query_log.is_file():
            return []
        matched: list[dict[str, Any]] = []
        for line_number, line in enumerate(query_log.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IcprError(f"invalid DNS query JSON {query_log}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise IcprError(f"DNS query must be a JSON object: {query_log}:{line_number}")
            try:
                recorded = parse_utc(str(row.get("recorded_utc", "")))
                qtype = int(row.get("qtype"))
            except (IcprError, TypeError, ValueError) as exc:
                raise IcprError(f"invalid DNS query schema {query_log}:{line_number}: {exc}") from exc
            if (
                start <= recorded <= end
                and str(row.get("name", "")).rstrip(".").lower() == "mask-h2.icloud.com"
                and qtype == 1
                and row.get("supported") is not False
            ):
                matched.append({**row, "line_number": line_number})
        return matched

    def _feed(
        self, date: str
    ) -> tuple[list[dict[str, str]] | None, str, str | None, str]:
        day_dir = self.feed_root / date
        feeds = sorted(day_dir.glob("*.csv")) if day_dir.is_dir() else []
        if not feeds:
            return None, "", "pending:same_day_apple_feed_missing", ""
        if len(feeds) != 1:
            return None, "", "pending:multiple_same_day_apple_feeds", ""
        try:
            digest = verify_sidecar(feeds[0])
            rows = _read_apple_feed(feeds[0])
            seen: dict[str, tuple[str, str, str]] = {}
            for row in rows:
                prefix = str(ipaddress.ip_network(row["ip_prefix"].strip(), strict=False))
                location = (row["country"], row["region"], row["city"])
                if prefix in seen and seen[prefix] != location:
                    raise IcprError(f"conflicting duplicate Apple prefix: {prefix}")
                seen[prefix] = location
                row["ip_prefix"] = prefix
            return rows, digest, None, str(feeds[0])
        except IcprError as exc:
            return None, "", f"integrity:{exc}", str(feeds[0])
        except (OSError, ValueError, KeyError, csv.Error) as exc:
            return None, "", f"integrity:invalid Apple feed {feeds[0]}: {exc}", str(
                feeds[0]
            )

    def _dated_asn(self, address: str, date: str) -> dict[str, str] | None:
        rows = [row for row in self.asn_rows if row.get("date") == date]
        ip = ipaddress.ip_address(address)
        matches: list[tuple[int, dict[str, str]]] = []
        for row in rows:
            try:
                network = ipaddress.ip_network(row.get("prefix", ""), strict=False)
            except ValueError:
                continue
            if network.version == ip.version and ip in network:
                matches.append((network.prefixlen, row))
        if not matches:
            return None
        longest = max(prefix_length for prefix_length, _ in matches)
        best = [row for prefix_length, row in matches if prefix_length == longest]
        if len({row.get("asn") for row in best}) != 1:
            return None
        return best[0]

    def _operator(self, asn: str) -> dict[str, str] | None:
        return self.operator_by_asn.get(str(asn))

    def _disclosure(self, record: dict[str, Any]) -> str | None:
        ground = self.config.get("objective_3_ground_truth", {})
        if not isinstance(ground, dict):
            return None
        required = (
            ground.get("true_country_code"),
            ground.get("true_time_zone"),
            ground.get("temporal_intersection_rule"),
        )
        permitted = ground.get("country_time_zone_permitted_apple_locations")
        boundary = ground.get("maintain_general_location_boundary")
        if not all(required) or not isinstance(permitted, list) or not permitted:
            return None
        if not all(
            isinstance(rule, dict)
            and any(rule.get(key) for key in ("country", "region", "city"))
            for rule in permitted
        ):
            return None
        if not isinstance(boundary, dict) or not any(
            boundary.get(key)
            for key in ("allowed_country_codes", "allowed_regions", "allowed_cities")
        ):
            return None
        location = {
            "country": record["advertised_country"],
            "region": record["advertised_region"],
            "city": record["advertised_city"],
        }
        if record["location_setting"] == "country_and_time_zone":
            matched = any(
                all(
                    not rule.get(key)
                    or _normalized_location_value(rule[key])
                    == _normalized_location_value(location[key])
                    for key in location
                )
                for rule in permitted
            )
            return "within_declared_country_time_zone" if matched else "outside_declared_country_time_zone"
        if record["location_setting"] != "maintain_general_location":
            return None
        country = _normalized_location_value(location["country"])
        city = _normalized_location_value(location["city"])
        true_country = _normalized_location_value(ground.get("true_country_code"))
        allowed_cities = {
            _normalized_location_value(value)
            for value in boundary.get("allowed_cities", [])
            if _normalized_location_value(value)
        }
        if not true_country or not allowed_cities:
            return None
        if not country or not city:
            return "unclassifiable"
        if country != true_country:
            return "inconsistent"
        if city in allowed_cities:
            return "city_level_consistent"
        return "primary_boundary_non_match"

    def pair_attempt(self, attempt_dir: Path, duplicate: bool = False) -> dict[str, Any]:
        metadata: dict[str, Any] = {"run_id": attempt_dir.name}
        record = _base_record(metadata, attempt_dir, read_events=False)
        try:
            verified_artifacts = verify_attempt(attempt_dir)
            loaded_metadata = json.loads(
                (attempt_dir / "metadata.json").read_text(encoding="utf-8")
            )
            if not isinstance(loaded_metadata, dict):
                raise IcprError("attempt metadata must be a JSON object")
            metadata = loaded_metadata
            record = _base_record(metadata, attempt_dir)
            record["client_manifest_sha256"] = verify_sidecar(
                attempt_dir / "manifest.sha256"
            )
            record["client_artifact_hashes"] = verified_artifacts
        except (IcprError, json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            return _corrupt_attempt_record(attempt_dir, str(exc), metadata)
        if duplicate:
            return _corrupt_attempt_record(attempt_dir, "duplicate client run_id", metadata)
        flags: list[str] = record["validation_flags"]
        record.update(
            operator_map_version=self.config["mapping"]["operator_map_version"],
            operator_map_sha256=self.operator_map_hash,
            operator_map_path=str(self.operator_map_path),
            origin_asn_dataset_version=self.config["mapping"].get(
                "origin_asn_dataset_version", ""
            ),
            origin_asn_dataset_sha256=self.asn_hash,
            origin_asn_dataset_path=str(self.asn_path),
            akamai_sibling_asns_snapshot=sorted(self.akamai_sibling_asns, key=int),
        )

        required_metadata = (
            "run_id",
            "campaign",
            "block_id",
            "attempt_number",
            "clock_status",
            "clock_evidence",
            "private_relay_state",
            "location_setting",
            "intended_ingress_group",
            "hostname",
            "url",
            "macos_version",
            "safari_version",
            "active_interface",
            "network_type",
            "real_public_ipv4",
            "freshness_method",
            "operator_condition_confirmation",
            "effective_dns",
            "approved_ingress_candidates",
            "capture_filter",
            "quic_block_state",
            "timeout_deadline_utc",
        )
        missing = [key for key in required_metadata if metadata.get(key) in (None, "")]
        try:
            client_start = parse_utc(record["client_start_utc"])
            start = parse_utc(record["safari_launch_utc"])
            capture_stopped = parse_utc(record["capture_stopped_utc"])
            end = parse_utc(record["client_end_utc"])
            if not client_start <= start <= capture_stopped <= end:
                raise IcprError("attempt event chronology is inconsistent")
        except IcprError as exc:
            missing.append(str(exc))
            client_start = start = capture_stopped = end = dt.datetime.now(dt.timezone.utc)
        if record["clock_status"] != "synchronized":
            missing.append("clock_status is not synchronized")
        clock_evidence = metadata.get("clock_evidence")
        if not isinstance(clock_evidence, dict):
            missing.append("clock_evidence is not an object")
        elif "On" not in str(clock_evidence.get("network_time", "")):
            missing.append("recorded macOS network time state is not enabled")
        if not record["end_condition_confirmation"]:
            missing.append("run_finished.end_condition_confirmation is missing")
        if missing:
            flags.extend(missing)
        if record["condition_changed"]:
            flags.append("condition changed during attempt")

        caddy_schema_errors = self._caddy_schema_errors(str(record["run_id"]))
        flags.extend(caddy_schema_errors)
        exact = self._exact_caddy(str(record["run_id"]))
        private_ip = self.config["server"].get("private_ipv4")
        if not private_ip:
            flags.append("server.private_ipv4 is not configured")
        else:
            try:
                private_ip = str(ipaddress.IPv4Address(private_ip))
            except (ipaddress.AddressValueError, TypeError) as exc:
                flags.append(f"invalid server.private_ipv4: {exc}")
                private_ip = None
        flows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        if private_ip:
            try:
                for row in sorted(exact, key=lambda item: float(item.get("ts", 0))):
                    transport, flow_key = self._server_flow(row, private_ip)
                    flows[flow_key].append(row)
                    request = row["request"]
                    record["server_delivery_sequence"].append(
                        {
                            "server_time_utc": epoch_to_utc(row["ts"]),
                            "remote_ip": request["remote_ip"],
                            "remote_port": int(str(request["remote_port"])),
                            "http_protocol": request["proto"],
                            "transport": transport,
                            "request_uuid": row.get("request_uuid", ""),
                            "flow_key": flow_key,
                            "caddy_record_sha256": row.get("_row_sha256", ""),
                            "caddy_artifact_sha256": row.get("_artifact_sha256", ""),
                            "caddy_artifact_path": row.get("_artifact", ""),
                            "caddy_line_number": row.get("_line_number", ""),
                        }
                    )
                record["server_delivery_count"] = len(record["server_delivery_sequence"])
            except (KeyError, TypeError, ValueError, IcprError) as exc:
                flags.append(f"invalid Caddy probe schema: {exc}")

        response = None
        response_path = attempt_dir / "response.json"
        if response_path.is_file():
            try:
                loaded_response = json.loads(response_path.read_text(encoding="utf-8"))
                if not isinstance(loaded_response, dict):
                    raise IcprError("response JSON must be an object")
                response = loaded_response
            except (IcprError, json.JSONDecodeError, OSError) as exc:
                flags.append(f"invalid response JSON: {exc}")
        selected: dict[str, Any] | None = None
        if response and response.get("request_uuid"):
            selected_rows = [
                row for row in exact if row.get("request_uuid") == response["request_uuid"]
            ]
            if len(selected_rows) == 1:
                selected = selected_rows[0]
            elif len(selected_rows) > 1:
                flags.append("duplicate Caddy request_uuid")
        elif len(exact) == 1:
            selected = exact[0]
        elif exact:
            flags.append("multiple Caddy rows without a response UUID")

        response_problems: list[str] = []
        if record["client_outcome"] == "success":
            if response is None:
                response_problems.append("successful attempt has no response JSON")
            else:
                required_response = (
                    "run_id",
                    "server_utc",
                    "server_unix_ms",
                    "remote_ip",
                    "remote_port",
                    "http_protocol",
                    "request_host",
                    "request_uri",
                    "request_uuid",
                )
                response_problems.extend(
                    f"response.{key} is missing"
                    for key in required_response
                    if response.get(key) in (None, "")
                )
        if response and response.get("run_id") != record["run_id"]:
            response_problems.append("response run_id does not equal client run_id")
        response_server_time: dt.datetime | None = None
        response_server_ms: float | None = None
        if response:
            try:
                response_server_time = _parse_response_server_utc(
                    response.get("server_utc", "")
                )
                response_server_ms = float(response["server_unix_ms"])
                utc_ms = response_server_time.timestamp() * 1000
                if abs(response_server_ms - utc_ms) > 2000:
                    response_problems.append(
                        "response server_utc and server_unix_ms differ by more than 2 seconds"
                    )
            except (IcprError, KeyError, TypeError, ValueError, OverflowError) as exc:
                response_problems.append(f"invalid response server timestamp: {exc}")
        if response and selected:
            request = selected.get("request") or {}
            comparisons = {
                "remote_ip": request.get("remote_ip"),
                "remote_port": str(request.get("remote_port", "")),
                "http_protocol": request.get("proto"),
                "request_host": self.config["server"]["hostname"],
                "request_uri": f"/probe/{record['run_id']}",
                "request_uuid": selected.get("request_uuid"),
            }
            for key, expected in comparisons.items():
                if str(response.get(key, "")) != str(expected):
                    response_problems.append(f"response.{key} does not match Caddy")
            try:
                delta_ms = abs(float(response["server_unix_ms"]) - float(selected["ts"]) * 1000)
                if delta_ms > 2000:
                    response_problems.append("response server time differs from Caddy by more than 2 seconds")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                response_problems.append(f"invalid response/Caddy timestamp: {exc}")
            try:
                if int(selected.get("status", 0)) != 200:
                    response_problems.append("selected Caddy response status is not 200")
            except (TypeError, ValueError) as exc:
                response_problems.append(f"invalid selected Caddy response status: {exc}")
        flags.extend(response_problems)

        triggered: list[str] = []
        if missing or response_problems or caddy_schema_errors or not private_ip or any(
            "invalid" in flag or "duplicate Caddy request_uuid" in flag for flag in flags
        ):
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
        if record["condition_changed"]:
            triggered.append("E08_CONDITION_CHANGED")
        if not exact or selected is None:
            triggered.append("E01_NO_SERVER_OBSERVATION")
        if len(flows) > 1 or "multiple Caddy rows without a response UUID" in flags:
            triggered.append("E02_MULTIPLE_SERVER_CONNECTIONS")
        selected_time: dt.datetime | None = None
        if selected:
            try:
                selected_time = dt.datetime.fromtimestamp(
                    float(selected.get("ts")), tz=dt.timezone.utc
                )
                if not start <= selected_time <= capture_stopped:
                    triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                    flags.append("selected Caddy request falls outside Safari-launch/capture interval")
                deadline = parse_utc(str(metadata.get("timeout_deadline_utc", "")))
                if selected_time > deadline:
                    triggered.append("E08_CONDITION_CHANGED")
                    flags.append("selected request occurred after the predeclared timeout")
            except (IcprError, TypeError, ValueError, OverflowError, OSError) as exc:
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"invalid selected Caddy timestamp: {exc}")
                selected_time = None

        freshness = None
        if selected and private_ip:
            request = selected.get("request") or {}
            try:
                transport, flow_key = self._server_flow(selected, private_ip)
                remote_ip = str(ipaddress.IPv4Address(str(request["remote_ip"])))
                record.update(
                    server_time_utc=epoch_to_utc(selected["ts"]),
                    server_remote_ip=remote_ip,
                    server_remote_port=int(str(request["remote_port"])),
                    server_transport=transport,
                    server_http_protocol=request["proto"],
                    server_flow_key=flow_key,
                    server_private_ipv4=private_ip,
                    response_status=int(selected.get("status", 0)),
                    caddy_record_sha256=selected["_row_sha256"],
                    caddy_artifact_sha256=selected["_artifact_sha256"],
                    caddy_artifact_path=selected["_artifact"],
                    caddy_line_number=selected["_line_number"],
                    request_uuid=selected.get("request_uuid", ""),
                    response_evidence=response or {},
                )
                freshness, ambiguous_connection = self._freshness(
                    row=selected, start=start, end=capture_stopped, private_ip=private_ip
                )
                if ambiguous_connection:
                    triggered.append("E02_MULTIPLE_SERVER_CONNECTIONS")
                    flags.append("multiple fresh connection identities on the selected 5-tuple")
                elif not freshness:
                    triggered.append("E03_NO_FRESH_FLOW")
                else:
                    record["freshness_evidence"] = freshness
            except (KeyError, TypeError, ValueError, IcprError) as exc:
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"server evidence parse failure: {exc}")

        client_packets, client_errors = load_packet_tree(attempt_dir, manifest_verified=True)
        if client_errors:
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.extend(client_errors)
        fallback_active = metadata.get("quic_block_state") == "targeted_ingress_udp_443"
        if fallback_active:
            firewall_state_path = attempt_dir / "firewall-state.json"
            try:
                firewall_state = json.loads(
                    firewall_state_path.read_text(encoding="utf-8")
                )
                if not isinstance(firewall_state, dict):
                    raise IcprError("PF evidence is not an object")
                record["fallback_pf_evidence"] = {
                    "anchor": firewall_state.get("anchor", ""),
                    "exact_rule": firewall_state.get("exact_rule", ""),
                    "targeted_state_reset_utc": firewall_state.get(
                        "targeted_state_reset_utc", ""
                    ),
                    "rule_statistics_before_cleanup_utc": firewall_state.get(
                        "rule_statistics_before_cleanup_utc", ""
                    ),
                    "rule_statistics_before_cleanup": firewall_state.get(
                        "rule_statistics_before_cleanup", {}
                    ),
                    "restored_utc": firewall_state.get("restored_utc", ""),
                }
            except (IcprError, OSError, json.JSONDecodeError, TypeError) as exc:
                firewall_state = {}
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"targeted PF evidence parse failure: {exc}")
        try:
            client_ingress_end = (
                selected_time
                if selected_time is not None and start <= selected_time <= capture_stopped
                else capture_stopped
            )
            record["client_ingress_attribution_end_utc"] = epoch_to_utc(
                client_ingress_end.timestamp()
            )
            contacts, fresh_contacts = self._client_ingress(
                metadata, client_packets, start, client_ingress_end
            )
        except (IcprError, TypeError, ValueError, OverflowError, OSError) as exc:
            contacts, fresh_contacts = [], []
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.append(f"client ingress evidence parse failure: {exc}")
        record["client_ingress_candidates"] = contacts
        record["client_fresh_ingress_candidates"] = fresh_contacts
        try:
            bounded_ips = self._bounded_attribution_candidate_ips(metadata)
        except IcprError as exc:
            bounded_ips = set()
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.append(f"bounded ingress candidate parse failure: {exc}")
        bounded_contacts = [
            contact for contact in contacts if contact["ingress_ip"] in bounded_ips
        ]
        bounded_fresh_contacts = [
            contact
            for contact in fresh_contacts
            if contact["ingress_ip"] in bounded_ips
        ]
        attribution_policy = record["ingress_attribution_policy"]
        if attribution_policy == "fresh_handshake_v1":
            attribution_contacts = bounded_fresh_contacts
        elif attribution_policy == "bounded_candidate_contact_v2":
            fresh_ips = {
                contact["ingress_ip"] for contact in bounded_fresh_contacts
            }
            if len(fresh_ips) == 1:
                attribution_contacts = bounded_fresh_contacts
            else:
                attribution_contacts = bounded_contacts
        elif attribution_policy == "legacy_candidate_contact_v1":
            attribution_contacts = contacts
        else:
            attribution_contacts = []
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.append(
                f"unknown ingress attribution policy: {attribution_policy!r}"
            )
        record["client_ingress_attribution_candidates"] = attribution_contacts
        ingress_unambiguous = (
            len({contact["ingress_ip"] for contact in attribution_contacts}) == 1
        )
        if ingress_unambiguous:
            observed_ips = {
                contact["ingress_ip"] for contact in attribution_contacts
            }
            chosen_ip = next(iter(observed_ips))
            chosen_contacts = [
                contact
                for contact in attribution_contacts
                if contact["ingress_ip"] == chosen_ip
            ]
            if fallback_active:
                attributable = [
                    contact for contact in chosen_contacts if contact["transport"] == "tcp"
                ]
            else:
                transports = {contact["transport"] for contact in chosen_contacts}
                attributable = chosen_contacts if len(transports) == 1 else []
            if attributable:
                record["observed_ingress_ip"] = chosen_ip
                record["ingress_transport"] = attributable[0]["transport"]
                record["ingress_5tuple"] = attributable[0]["five_tuple"]
            else:
                ingress_unambiguous = False
        intended_ip = record["intended_ingress_ip"]
        record["pin_contact_status"] = self._pin_contact_status(
            intended_ip, contacts
        )
        record["fresh_pin_contact_status"] = self._pin_contact_status(
            intended_ip, fresh_contacts
        )
        if not ingress_unambiguous or (
            intended_ip and record["observed_ingress_ip"] != intended_ip
        ):
            triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
            if not attribution_contacts:
                flags.append(
                    "no client-to-ingress evidence satisfied the recorded attribution policy"
                )
            elif len(
                {contact["ingress_ip"] for contact in attribution_contacts}
            ) > 1:
                flags.append(
                    "client-to-ingress evidence satisfying the recorded attribution policy reached multiple candidate IPv4 addresses"
                )
            elif intended_ip and record["observed_ingress_ip"] != intended_ip:
                flags.append(
                    "the client-to-ingress evidence did not reach the intended pin"
                )
        try:
            approved_pin_addresses = [
                str(ipaddress.IPv4Address(value))
                for value in (metadata.get("approved_pin_group_addresses") or [])
            ]
        except (ipaddress.AddressValueError, TypeError) as exc:
            approved_pin_addresses = []
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.append(f"invalid approved pin snapshot: {exc}")
        if (
            record["intended_ingress_group"] != "unpinned"
            and intended_ip not in approved_pin_addresses
        ):
            triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
            flags.append("intended pin is absent from the recorded approved pin snapshot")
        if fallback_active:
            try:
                mask_h2_queries = self._mask_h2_queries(attempt_dir, start, capture_stopped)
                record["fallback_mask_h2_dns_queries"] = mask_h2_queries
            except (IcprError, OSError) as exc:
                mask_h2_queries = []
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"fallback DNS-query evidence parse failure: {exc}")
            if record["ingress_transport"] != "tcp":
                triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
                flags.append("targeted fallback did not show TCP/443 contact to the pinned ingress")
            statistics = record["fallback_pf_evidence"].get(
                "rule_statistics_before_cleanup", {}
            )
            if not record["fallback_pf_evidence"].get("targeted_state_reset_utc"):
                triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
                flags.append("targeted fallback has no recorded destination-state reset")
            try:
                blocked_packets = (
                    int(statistics.get("packets", 0))
                    if isinstance(statistics, dict)
                    else 0
                )
            except (TypeError, ValueError):
                blocked_packets = 0
            if blocked_packets < 1:
                triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
                flags.append("targeted fallback PF rule has no recorded blocked packet")

        real_ip = metadata.get("real_public_ipv4")
        if real_ip:
            try:
                real_ip = str(ipaddress.IPv4Address(real_ip))
                record["real_public_ipv4"] = real_ip
                if record["server_remote_ip"] == real_ip:
                    triggered.append("E05_REAL_IP_AT_DESTINATION")
            except (ipaddress.AddressValueError, TypeError) as exc:
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"invalid client real_public_ipv4: {exc}")

        feed_rows = None
        if record["server_time_utc"]:
            feed_date = record["server_time_utc"][:10]
            record["apple_feed_date"] = feed_date
            feed_rows, feed_hash, feed_error, feed_path = self._feed(feed_date)
            record["apple_feed_hash"] = feed_hash
            record["apple_feed_path"] = feed_path
            if feed_error:
                if feed_error.startswith("integrity:"):
                    triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                    record["pending_reason"] = ""
                else:
                    record["pending_reason"] = feed_error.removeprefix("pending:")
                flags.append(feed_error)
            elif record["server_remote_ip"]:
                feed_mapping_failed = False
                try:
                    feed_match = longest_prefix_match(
                        record["server_remote_ip"], feed_rows or []
                    )
                except (ValueError, TypeError) as exc:
                    feed_match = None
                    feed_mapping_failed = True
                    triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                    flags.append(f"Apple feed mapping failure: {exc}")
                if not feed_match:
                    if not feed_mapping_failed:
                        triggered.append("E06_EGRESS_NOT_IN_FEED")
                else:
                    record.update(
                        matched_prefix=feed_match.get("ip_prefix", ""),
                        advertised_country=feed_match.get("country", ""),
                        advertised_region=feed_match.get("region", ""),
                        advertised_city=feed_match.get("city", ""),
                        apple_feed_match=feed_match,
                    )

        if self.asn_error:
            triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
            flags.append(self.asn_error)
        if record["apple_feed_date"] and record["observed_ingress_ip"] and record["server_remote_ip"]:
            try:
                ingress_origin = self._dated_asn(
                    record["observed_ingress_ip"], record["apple_feed_date"]
                )
                egress_origin = self._dated_asn(
                    record["server_remote_ip"], record["apple_feed_date"]
                )
            except (ValueError, TypeError) as exc:
                ingress_origin = egress_origin = None
                triggered.append("E07_CLOCK_OR_LOG_CORRUPTION")
                flags.append(f"dated ASN mapping failure: {exc}")
            if not ingress_origin or not egress_origin:
                record["pending_reason"] = "dated_asn_mapping_missing"
                flags.append("dated ingress or egress ASN mapping is missing")
            else:
                record["ingress_asn"] = ingress_origin.get("asn", "")
                record["egress_asn"] = egress_origin.get("asn", "")
                record["ingress_origin_mapping"] = ingress_origin
                record["egress_origin_mapping"] = egress_origin
                intended_group = record["intended_ingress_group"]
                if intended_group == "apple_as714" and record["ingress_asn"] != "714":
                    triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
                    flags.append("Apple AS714 pin resolved to an ingress ASN other than 714")
                if (
                    intended_group == "akamai"
                    and record["ingress_asn"] not in self.akamai_sibling_asns
                ):
                    triggered.append("E04_WRONG_OR_UNKNOWN_INGRESS")
                    flags.append(
                        "Akamai pin resolved outside the frozen Akamai sibling ASN set"
                    )
                ingress_operator = self._operator(record["ingress_asn"])
                egress_operator = self._operator(record["egress_asn"])
                if not ingress_operator or not egress_operator:
                    record["pending_reason"] = "operator_mapping_missing"
                    flags.append("ingress or egress operator mapping is missing")
                else:
                    record["ingress_operator"] = ingress_operator.get("operator_id", "")
                    record["egress_operator"] = egress_operator.get("operator_id", "")
                    record["ingress_operator_rule"] = ingress_operator.get("mapping_rule", "")
                    record["egress_operator_rule"] = egress_operator.get("mapping_rule", "")
                    record["ingress_operator_mapping"] = ingress_operator
                    record["egress_operator_mapping"] = egress_operator
                    record["same_operator"] = (
                        record["ingress_operator"] == record["egress_operator"]
                    )

        if record["matched_prefix"]:
            record["disclosure_class"] = self._disclosure(record) or ""
            if not record["disclosure_class"]:
                record["pending_reason"] = "objective_3_configuration_incomplete"
                flags.append("Objective 3 ground-truth configuration is incomplete")

        precedence = self.config["exclusion_precedence"]
        triggered = list(dict.fromkeys(triggered))
        record["triggered_exclusions"] = triggered
        selected_exclusion = next((code for code in precedence if code in triggered), "")
        if selected_exclusion:
            record["disposition"] = "excluded"
            record["exclusion_reason"] = selected_exclusion
        elif record.get("pending_reason"):
            record["disposition"] = "pending"
        else:
            record["disposition"] = "accepted"
        record["protocol_classification"] = _protocol(record)
        record["protocol_classification_basis"] = _protocol_basis(record)
        return record

    def run(self) -> list[dict[str, Any]]:
        attempts = self._attempt_dirs()
        by_run: dict[str, list[Path]] = defaultdict(list)
        for path in attempts:
            try:
                metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
                run_id = (
                    str(metadata.get("run_id") or path.name)
                    if isinstance(metadata, dict)
                    else path.name
                )
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                run_id = path.name
            by_run[run_id].append(path)
        records = []
        for run_id, paths in sorted(by_run.items()):
            duplicate = len(paths) > 1
            for path in paths:
                try:
                    records.append(self.pair_attempt(path, duplicate=duplicate))
                except (
                    IcprError,
                    json.JSONDecodeError,
                    OSError,
                    KeyError,
                    TypeError,
                    ValueError,
                    OverflowError,
                ) as exc:
                    records.append(_corrupt_attempt_record(path, str(exc)))
        return records

    def write_outputs(self, records: list[dict[str, Any]]) -> dict[str, Path]:
        derived = self.root / "derived"
        reports = self.root / "reports"
        pairs_path = derived / "pairs_v1.csv"
        exclusions_path = derived / "exclusions_v1.csv"
        protocols_path = derived / "protocol_classification_v1.csv"
        summary_path = derived / "daily_summary_v1.json"
        report_path = reports / "validation_report_v1.md"
        provenance_fields = [
            "run_mode",
            "session",
            "slot_id",
            "retry_number",
            "safari_launch_utc",
            "capture_stopped_utc",
            "client_ingress_attribution_end_utc",
            "request_uuid",
            "protocol_classification",
            "protocol_classification_basis",
            "pending_reason",
            "triggered_exclusions",
            "validation_flags",
            "client_outcome",
            "condition_changed",
            "end_condition_confirmation",
            "controller_version",
            "config_version",
            "config_sha256",
            "execution_plan_version",
            "execution_plan_sha256",
            "pin_list_version",
            "pin_list_sha256",
            "approved_ingress_candidates",
            "approved_pin_group_addresses",
            "capture_recent_candidates",
            "capture_recent_candidate_provenance",
            "capture_recent_candidate_policy",
            "capture_candidate_scope",
            "ingress_attribution_policy",
            "effective_dns",
            "capture_filter",
            "quic_block_state",
            "fallback_pf_evidence",
            "timeout_deadline_utc",
            "freshness_method",
            "network_type",
            "active_interface",
            "macos_version",
            "safari_version",
            "real_public_ipv4",
            "client_manifest_sha256",
            "client_artifact_hashes",
            "client_ingress_candidates",
            "client_fresh_ingress_candidates",
            "client_ingress_attribution_candidates",
            "fresh_pin_contact_status",
            "server_private_ipv4",
            "server_delivery_count",
            "server_delivery_sequence",
            "caddy_record_sha256",
            "caddy_artifact_sha256",
            "caddy_artifact_path",
            "caddy_line_number",
            "response_evidence",
            "fallback_mask_h2_dns_queries",
            "apple_feed_match",
            "apple_feed_path",
            "origin_asn_dataset_version",
            "origin_asn_dataset_sha256",
            "origin_asn_dataset_path",
            "akamai_sibling_asns_snapshot",
            "ingress_origin_mapping",
            "egress_origin_mapping",
            "ingress_operator_rule",
            "egress_operator_rule",
            "ingress_operator_mapping",
            "egress_operator_mapping",
            "operator_map_sha256",
            "operator_map_path",
            "attempt_path",
        ]
        extended_fields = list(dict.fromkeys(REQUIRED_PAIR_FIELDS + provenance_fields))
        write_csv(
            pairs_path,
            (row for row in records if row["disposition"] != "excluded"),
            extended_fields,
        )
        write_csv(
            exclusions_path,
            (row for row in records if row["disposition"] == "excluded"),
            extended_fields,
        )
        write_csv(
            protocols_path,
            records,
            [
                "run_id",
                "campaign",
                "run_mode",
                "session",
                "block_id",
                "intended_ingress_group",
                "location_setting",
                "private_relay_state",
                "ingress_transport",
                "server_http_protocol",
                "server_transport",
                "server_delivery_count",
                "server_delivery_sequence",
                "quic_block_state",
                "fallback_pf_evidence",
                "protocol_classification",
                "protocol_classification_basis",
                "disposition",
                "exclusion_reason",
                "pipeline_version",
            ],
        )
        objective_outputs = write_objective_eligibility(records, derived)
        dimension_names = (
            "pin_mode",
            "intended_ingress_group",
            "location_setting",
            "private_relay_state",
            "block_id",
            "session",
            "quic_block_state",
            "protocol_classification",
        )

        def new_strata() -> dict[str, defaultdict[str, Counter[str]]]:
            return {
                name: defaultdict(Counter)
                for name in dimension_names
            }

        def increment_bucket(counter: Counter[str], row: dict[str, Any]) -> None:
            counter["attempts"] += 1
            counter[str(row.get("disposition") or "pending")] += 1

        def materialize_strata(
            strata: dict[str, defaultdict[str, Counter[str]]]
        ) -> dict[str, dict[str, dict[str, int]]]:
            return {
                dimension: {
                    value: dict(counts)
                    for value, counts in sorted(values.items())
                }
                for dimension, values in strata.items()
            }

        days: dict[str, dict[str, Any]] = {}
        overall_strata = new_strata()
        totals: Counter[str] = Counter()
        exclusions: Counter[str] = Counter()
        unpinned_sequence: list[dict[str, Any]] = []
        for row in records:
            day = (row.get("client_start_utc") or "unknown")[:10]
            if day not in days:
                days[day] = {
                    "attempt_counts": Counter(),
                    "exclusion_counts": Counter(),
                    "strata": new_strata(),
                }
            increment_bucket(days[day]["attempt_counts"], row)
            increment_bucket(totals, row)
            if row["exclusion_reason"]:
                exclusions[row["exclusion_reason"]] += 1
                days[day]["exclusion_counts"][row["exclusion_reason"]] += 1

            values = {
                "pin_mode": (
                    "unpinned"
                    if row.get("intended_ingress_group") == "unpinned"
                    else "pinned"
                ),
                "intended_ingress_group": str(
                    row.get("intended_ingress_group") or "unspecified"
                ),
                "location_setting": str(row.get("location_setting") or "unspecified"),
                "private_relay_state": str(
                    row.get("private_relay_state") or "unspecified"
                ),
                "block_id": str(row.get("block_id") or "unspecified"),
                "session": str(row.get("session") or "unspecified"),
                "quic_block_state": str(
                    row.get("quic_block_state") or "unspecified"
                ),
                "protocol_classification": str(
                    row.get("protocol_classification") or "unspecified"
                ),
            }
            for dimension, value in values.items():
                increment_bucket(overall_strata[dimension][value], row)
                increment_bucket(days[day]["strata"][dimension][value], row)

            if (
                values["pin_mode"] == "unpinned"
                and row.get("private_relay_state") == "on"
            ):
                unpinned_sequence.append(
                    {
                        "run_id": row.get("run_id", ""),
                        "client_start_utc": row.get("client_start_utc", ""),
                        "server_time_utc": row.get("server_time_utc", ""),
                        "session": row.get("session", ""),
                        "private_relay_state": row.get("private_relay_state", ""),
                        "location_setting": row.get("location_setting", ""),
                        "disposition": row.get("disposition", ""),
                        "exclusion_reason": row.get("exclusion_reason", ""),
                        "observed_ingress_ip": row.get("observed_ingress_ip", ""),
                        "server_remote_ip": row.get("server_remote_ip", ""),
                        "matched_prefix": row.get("matched_prefix", ""),
                        "advertised_country": row.get("advertised_country", ""),
                        "advertised_region": row.get("advertised_region", ""),
                        "advertised_city": row.get("advertised_city", ""),
                        "disclosure_class": row.get("disclosure_class", ""),
                    }
                )
        unpinned_sequence.sort(
            key=lambda row: (
                row.get("server_time_utc") or row.get("client_start_utc") or "",
                row.get("run_id") or "",
            )
        )
        objective_ground = self.config.get("objective_3_ground_truth")
        temporal_declaration = (
            objective_ground.get("temporal_intersection_rule")
            if isinstance(objective_ground, dict)
            else None
        )
        temporal_intersection = _temporal_intersection(
            temporal_declaration, unpinned_sequence
        )
        materialized_days = {
            day: {
                "attempt_counts": dict(values["attempt_counts"]),
                "exclusion_counts": dict(values["exclusion_counts"]),
                "strata": materialize_strata(values["strata"]),
            }
            for day, values in sorted(days.items())
        }
        summary = {
            "pipeline_version": PIPELINE_VERSION,
            "attempt_counts": dict(totals),
            "exclusion_counts": dict(exclusions),
            "strata": materialize_strata(overall_strata),
            "days": materialized_days,
            "unpinned_temporal_sequence": unpinned_sequence,
            "temporal_intersection": temporal_intersection,
        }
        write_json(summary_path, summary)
        lines = [
            "# Step 9 pairing validation report v1",
            "",
            f"Attempts: {totals['attempts']}",
            f"Accepted: {totals['accepted']}",
            f"Excluded: {totals['excluded']}",
            f"Pending: {totals['pending']}",
            "",
            "## Attempt results",
            "",
            "| run_id | disposition | protocol | reason |",
            "|---|---|---|---|",
        ]
        for row in records:
            reason = row["exclusion_reason"] or row.get("pending_reason", "")
            lines.append(
                f"| {row['run_id']} | {row['disposition']} | "
                f"{row['protocol_classification']} | {reason} |"
            )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        sidecars = {
            "pairs_sha256": write_sidecar(pairs_path),
            "exclusions_sha256": write_sidecar(exclusions_path),
            "protocols_sha256": write_sidecar(protocols_path),
            "summary_sha256": write_sidecar(summary_path),
            "report_sha256": write_sidecar(report_path),
        }
        return {
            "pairs": pairs_path,
            "exclusions": exclusions_path,
            "protocols": protocols_path,
            "summary": summary_path,
            "report": report_path,
            **objective_outputs,
            **sidecars,
        }
