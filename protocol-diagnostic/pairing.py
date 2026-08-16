#!/usr/bin/env python3
"""Strict pairing and classification for the standalone protocol diagnostic.

This module intentionally does not use or write the campaign's derived data.  Raw
diagnostic attempts are manifest-verified with ``experiment/icprlib.py``; server
logs and captures are accepted only after their SHA-256 sidecars verify.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_ROOT = REPO_ROOT / "experiment"
if str(EXPERIMENT_ROOT) not in sys.path:
    sys.path.insert(0, str(EXPERIMENT_ROOT))

import icprlib  # noqa: E402


DEFAULT_CLIENT_ROOT = REPO_ROOT / "protocol-diagnostic" / "client"
DEFAULT_SERVER_ROOT = REPO_ROOT / "server" / "recovery-data"
DEFAULT_DERIVED_ROOT = REPO_ROOT / "protocol-diagnostic" / "derived"
LIVE_CADDY_PREFIX_ROOT = DEFAULT_SERVER_ROOT / "live-caddy-prefixes"
APPLE_FIELDS = ("ip_prefix", "country", "region", "city")
GATED_H3_ANALYSIS_FAMILIES = {"h3_required", "h3_response_probe"}
CSV_FIELDS = (
    "slot_id",
    "run_id",
    "attempt_number",
    "retry_number",
    "condition",
    "intended_ingress_ipv4",
    "observed_ingress",
    "pf_counter_result",
    "outer_transport",
    "outer_targets",
    "server_delivery_sequence",
    "caddy_http_version",
    "server_pcap_transport",
    "observed_egress_ipv4",
    "same_day_catalogue_match",
    "direct_bypass",
    "classification",
    "acceptance",
    "ambiguities",
    "evidence",
)


class PairingError(RuntimeError):
    """An integrity or schema failure which must not be silently weakened."""


def _utc(value: Any) -> dt.datetime:
    try:
        return icprlib.parse_utc(str(value))
    except icprlib.IcprError as exc:
        raise PairingError(str(exc)) from exc


def _ipv4(value: Any, field: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise PairingError(f"invalid {field}: {value!r}") from exc


def _integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _truth(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes"}


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _resolve_metadata_path(value: Any, attempt_dir: Path) -> Path:
    path = Path(str(value))
    if path.is_absolute():
        return path
    repo_path = REPO_ROOT / path
    return repo_path if repo_path.exists() else attempt_dir / path


def read_apple_feed(path: Path) -> list[dict[str, str]]:
    """Read Apple's native headerless feed or a fixture with explicit headers."""

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            raw = [row for row in csv.reader(handle) if any(cell.strip() for cell in row)]
    except (OSError, UnicodeError, csv.Error) as exc:
        raise PairingError(f"unable to read Apple feed {path}: {exc}") from exc
    if not raw:
        raise PairingError(f"Apple feed contains no rows: {path}")
    first = [cell.lstrip("\ufeff").strip().lower() for cell in raw[0]]
    if set(APPLE_FIELDS).issubset(first):
        indexes = {name: first.index(name) for name in APPLE_FIELDS}
        rows = [
            {name: row[indexes[name]] if indexes[name] < len(row) else "" for name in APPLE_FIELDS}
            for row in raw[1:]
        ]
    else:
        rows = []
        for line_number, row in enumerate(raw, 1):
            if len(row) < 4 or any(cell.strip() for cell in row[4:]):
                raise PairingError(f"invalid native Apple feed row {path}:{line_number}")
            rows.append(dict(zip(APPLE_FIELDS, row[:4], strict=True)))
    if not rows:
        raise PairingError(f"Apple feed contains no data: {path}")
    return rows


def catalogue_match(address: str, rows: Sequence[dict[str, str]]) -> dict[str, str] | None:
    """Return the unique longest-prefix Apple catalogue match, else ``None``."""

    ip = ipaddress.IPv4Address(address)
    matches: list[tuple[int, dict[str, str]]] = []
    for row in rows:
        try:
            network = ipaddress.ip_network(row.get("ip_prefix", ""), strict=False)
        except ValueError:
            continue
        if network.version == 4 and ip in network:
            matches.append((network.prefixlen, row))
    if not matches:
        return None
    longest = max(length for length, _ in matches)
    best = [row for length, row in matches if length == longest]
    normalized = {
        (str(ipaddress.ip_network(row["ip_prefix"], strict=False)), row["country"], row["region"], row["city"])
        for row in best
    }
    if len(normalized) != 1:
        return None
    prefix, country, region, city = next(iter(normalized))
    return {"ip_prefix": prefix, "country": country, "region": region, "city": city}


def verify_same_day_feed(metadata: dict[str, Any], attempt_dir: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    feed_path = _resolve_metadata_path(metadata.get("apple_feed_path", ""), attempt_dir)
    recorded_hash = str(metadata.get("apple_feed_sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", recorded_hash):
        raise PairingError("metadata.apple_feed_sha256 is missing or invalid")
    try:
        actual_hash = icprlib.verify_sidecar(feed_path)
    except icprlib.IcprError as exc:
        raise PairingError(str(exc)) from exc
    if actual_hash != recorded_hash:
        raise PairingError("metadata Apple feed hash does not match verified feed")
    trial_date = _utc(metadata.get("safari_launch_requested_utc")).date().isoformat()
    if feed_path.parent.name != trial_date and trial_date not in feed_path.name:
        raise PairingError(f"Apple feed is not the same-day snapshot for {trial_date}")
    return read_apple_feed(feed_path), {"path": str(feed_path), "sha256": actual_hash}


def normalize_packet(raw: dict[str, Any], *, artifact: str = "", artifact_sha256: str = "") -> dict[str, Any]:
    """Normalize tshark rows and compact JSON fixtures into a pure-testable form."""

    def first(*names: str) -> Any:
        for name in names:
            if raw.get(name) not in (None, ""):
                return raw[name]
        return None

    tcp_src = _integer(first("tcp.srcport", "tcp_srcport"))
    tcp_dst = _integer(first("tcp.dstport", "tcp_dstport"))
    udp_src = _integer(first("udp.srcport", "udp_srcport"))
    udp_dst = _integer(first("udp.dstport", "udp_dstport"))
    transport = str(raw.get("transport") or ("tcp" if tcp_src is not None else "udp" if udp_src is not None else ""))
    long_type = first("quic.long.packet_type", "quic_long_packet_type")
    quic_initial = _truth(raw.get("quic_initial")) or str(long_type) == "0"
    return {
        "frame_number": _integer(first("frame.number", "frame_number")),
        "time_epoch": float(first("frame.time_epoch", "time_epoch")) if first("frame.time_epoch", "time_epoch") not in (None, "") else None,
        "src_ip": first("ip.src", "src_ip"),
        "dst_ip": first("ip.dst", "dst_ip"),
        "transport": transport,
        "src_port": tcp_src if transport == "tcp" else udp_src,
        "dst_port": tcp_dst if transport == "tcp" else udp_dst,
        "tcp_syn": _truth(first("tcp.flags.syn", "tcp_syn")),
        "tcp_ack": _truth(first("tcp.flags.ack", "tcp_ack")),
        "quic_initial": quic_initial,
        "quic_dcid": first("quic.dcid", "quic_dcid"),
        "artifact": artifact,
        "artifact_sha256": artifact_sha256,
    }


TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "udp.srcport",
    "udp.dstport",
    "quic.long.packet_type",
    "quic.dcid",
)


def tshark_packets(path: Path, artifact_hash: str, display_filter: str | None = None) -> list[dict[str, Any]]:
    argv = ["tshark", "-r", str(path)]
    if display_filter:
        argv.extend(["-Y", display_filter])
    argv.extend(["-T", "fields", "-E", "header=y", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=f"])
    for field in TSHARK_FIELDS:
        argv.extend(["-e", field])
    try:
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise PairingError(f"tshark failed for {path}: {exc}") from exc
    if result.returncode != 0:
        raise PairingError(f"tshark failed for {path}: {result.stderr.strip()}")
    return [normalize_packet(dict(row), artifact=str(path), artifact_sha256=artifact_hash) for row in csv.DictReader(result.stdout.splitlines(), delimiter="\t", quotechar='"')]


def client_contacts(
    packets: Sequence[dict[str, Any]], candidate_ips: Iterable[str], origin_ip: str, intended_ip: str,
    candidate_hostname_map: dict[str, Any] | None = None,
    attribution_start_epoch: float | None = None,
    attribution_end_epoch: float | None = None,
) -> dict[str, Any]:
    """Extract ordered candidate contacts without equating capture scope with attribution.

    A candidate contact is attributable only when its IP has predeclared hostname
    provenance and it occurs inside the reset-to-observation attribution window.
    Direct-origin setup attempts are retained across the entire attempt capture.
    """

    candidates = {_ipv4(value, "capture candidate") for value in candidate_ips}
    origin = _ipv4(origin_ip, "origin_public_ipv4")
    candidates.discard(origin)
    intended = _ipv4(intended_ip, "intended_ingress_ipv4")
    hostname_map = candidate_hostname_map or {}
    ordered_packets = sorted(
        packets,
        key=lambda item: (
            item.get("time_epoch") is None,
            item.get("time_epoch") or 0,
            item.get("frame_number") or 0,
        ),
    )
    contacts: list[dict[str, Any]] = []
    direct: list[dict[str, Any]] = []
    for packet in ordered_packets:
        if packet.get("dst_ip") == origin and packet.get("dst_port") == 443:
            direct.append(
                {
                    "time_epoch": packet.get("time_epoch"),
                    "frame_number": packet.get("frame_number"),
                    "transport": packet.get("transport"),
                    "kind": "any_outbound_origin_443_contact",
                    "destination_ip": origin,
                    "source_port": packet.get("src_port"),
                    "destination_port": 443,
                }
            )
        setup_kind = None
        if packet.get("transport") == "tcp" and packet.get("dst_port") == 443 and packet.get("tcp_syn") and not packet.get("tcp_ack"):
            setup_kind = "tcp_syn"
        elif (
            packet.get("transport") == "udp"
            and packet.get("dst_port") == 443
            and packet.get("quic_initial")
            and packet.get("quic_dcid")
        ):
            setup_kind = "udp_quic_initial"
        if not setup_kind:
            continue
        item = {
            "time_epoch": packet.get("time_epoch"),
            "frame_number": packet.get("frame_number"),
            "transport": "tcp" if setup_kind == "tcp_syn" else "udp",
            "kind": setup_kind,
            "destination_ip": packet.get("dst_ip"),
            "source_port": packet.get("src_port"),
            "destination_port": 443,
        }
        timestamp = packet.get("time_epoch")
        in_window = timestamp is not None
        if attribution_start_epoch is not None:
            in_window = in_window and float(timestamp) >= attribution_start_epoch
        if attribution_end_epoch is not None:
            in_window = in_window and float(timestamp) <= attribution_end_epoch
        if packet.get("dst_ip") in candidates and in_window:
            replies = [
                candidate
                for candidate in ordered_packets
                if candidate.get("time_epoch") is not None
                and timestamp is not None
                and float(candidate["time_epoch"]) >= float(timestamp)
                and (
                    attribution_end_epoch is None
                    or float(candidate["time_epoch"]) <= attribution_end_epoch
                )
                and candidate.get("transport") == packet.get("transport")
                and candidate.get("src_ip") == packet.get("dst_ip")
                and candidate.get("dst_ip") == packet.get("src_ip")
                and candidate.get("src_port") == 443
                and candidate.get("dst_port") == packet.get("src_port")
            ]
            bidirectional = bool(replies)
            established = False
            handshake_evidence: dict[str, Any] | None = None
            if setup_kind == "tcp_syn" and replies:
                syn_acks = [
                    candidate
                    for candidate in replies
                    if candidate.get("tcp_syn") and candidate.get("tcp_ack")
                ]
                for syn_ack in syn_acks:
                    final_acks = [
                        candidate
                        for candidate in ordered_packets
                        if candidate.get("time_epoch") is not None
                        and float(candidate["time_epoch"])
                        >= float(syn_ack["time_epoch"])
                        and (
                            attribution_end_epoch is None
                            or float(candidate["time_epoch"]) <= attribution_end_epoch
                        )
                        and candidate.get("transport") == "tcp"
                        and candidate.get("src_ip") == packet.get("src_ip")
                        and candidate.get("dst_ip") == packet.get("dst_ip")
                        and candidate.get("src_port") == packet.get("src_port")
                        and candidate.get("dst_port") == 443
                        and candidate.get("tcp_ack")
                        and not candidate.get("tcp_syn")
                    ]
                    if not final_acks:
                        continue
                    final_ack = final_acks[0]
                    established = True
                    handshake_evidence = {
                        "syn": {
                            "frame_number": packet.get("frame_number"),
                            "time_epoch": timestamp,
                        },
                        "syn_ack": {
                            "frame_number": syn_ack.get("frame_number"),
                            "time_epoch": syn_ack.get("time_epoch"),
                        },
                        "ack": {
                            "frame_number": final_ack.get("frame_number"),
                            "time_epoch": final_ack.get("time_epoch"),
                        },
                    }
                    break
            names = hostname_map.get(str(packet.get("dst_ip")), [])
            if not isinstance(names, list):
                names = []
            contacts.append(
                {
                    **item,
                    "intended": packet.get("dst_ip") == intended,
                    "hostnames": sorted({str(name).rstrip(".").lower() for name in names if name}),
                    "attributable": bool(names),
                    "bidirectional": bidirectional,
                    "established": established,
                    "tcp_handshake_evidence": handshake_evidence,
                }
            )
    observed = []
    for item in contacts:
        if item["destination_ip"] not in observed:
            observed.append(item["destination_ip"])
    attributable = [item for item in contacts if item["attributable"]]
    tcp_attempt_flows = {
        (item["destination_ip"], item["source_port"])
        for item in attributable
        if item["transport"] == "tcp"
    }
    tcp_established_flows = {
        (item["destination_ip"], item["source_port"])
        for item in attributable
        if item["transport"] == "tcp" and item.get("established")
    }
    transports = {item["transport"] for item in attributable}
    outer_transport = "none" if not transports else next(iter(transports)) if len(transports) == 1 else "mixed"
    return {
        "contacts": contacts,
        "attributable_contacts": attributable,
        "direct_origin_contacts": direct,
        "observed_ingress_ips": observed,
        "outer_transport": outer_transport,
        "attributable_tcp": any(item["transport"] == "tcp" for item in attributable),
        "attributable_tcp_flows": [
            {"destination_ip": destination_ip, "source_port": source_port}
            for destination_ip, source_port in sorted(tcp_attempt_flows)
        ],
        "attributable_established_tcp_flows": [
            {"destination_ip": destination_ip, "source_port": source_port}
            for destination_ip, source_port in sorted(tcp_established_flows)
        ],
        "unambiguous_tcp_fallback": len(tcp_established_flows) == 1,
        "alternative_udp_attempt": any(
            item["transport"] == "udp" and not item["intended"]
            for item in attributable
        ),
        "alternative_udp_failover": any(
            item["transport"] == "udp"
            and not item["intended"]
            and item.get("bidirectional")
            for item in attributable
        ),
    }


def tagged_caddy_sequence(
    records: Sequence[dict[str, Any]], metadata: dict[str, Any], server_private_ip: str
) -> list[dict[str, Any]]:
    """Retain every tagged destination delivery in deterministic timestamp order."""

    run_id = str(metadata.get("run_id", ""))
    expected_uri = f"/probe/{run_id}"
    tagged = [
        row
        for row in records
        if row.get("run_id") == run_id
        and isinstance(row.get("request"), dict)
        and row["request"].get("uri") == expected_uri
    ]
    tagged.sort(
        key=lambda row: (
            not isinstance(row.get("ts"), (int, float)),
            float(row.get("ts", 0)) if isinstance(row.get("ts"), (int, float)) else 0,
            str(row.get("_artifact", "")),
            int(row.get("_line_number", 0) or 0),
        )
    )
    sequence: list[dict[str, Any]] = []
    for row in tagged:
        request = row["request"]
        proto = str(request.get("proto", ""))
        transport = "udp" if proto == "HTTP/3.0" else "tcp"
        timestamp = row.get("ts")
        try:
            timestamp_utc = (
                dt.datetime.fromtimestamp(float(timestamp), tz=dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except (TypeError, ValueError, OverflowError, OSError):
            timestamp_utc = None
        sequence.append(
            {
                "timestamp_epoch": timestamp,
                "timestamp_utc": timestamp_utc,
                "http_protocol": proto,
                "transport": transport,
                "five_tuple": {
                    "transport": transport,
                    "source_ip": request.get("remote_ip"),
                    "source_port": request.get("remote_port"),
                    "destination_ip": server_private_ip,
                    "destination_port": 443,
                },
                "request_uuid": row.get("request_uuid"),
                "artifact_path": row.get("_artifact"),
                "artifact_sha256": row.get("_artifact_sha256"),
                "row_sha256": row.get("_row_sha256"),
                "line_number": row.get("_line_number"),
            }
        )
    return sequence


def exact_caddy_pair(records: Sequence[dict[str, Any]], metadata: dict[str, Any], response: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Select exactly one Caddy row by run ID and response UUID/five-tuple."""

    errors: list[str] = []
    run_id = str(metadata.get("run_id", ""))
    uuid = str(response.get("request_uuid", ""))
    expected_uri = f"/probe/{run_id}"
    if not run_id or not uuid:
        return None, ["missing run_id or response request_uuid"]
    tagged = []
    for row in records:
        request = row.get("request")
        if not isinstance(request, dict):
            continue
        if row.get("run_id") == run_id and request.get("uri") == expected_uri:
            tagged.append(row)
    if len(tagged) != 1:
        return None, [f"expected one tagged Caddy destination row, found {len(tagged)}"]
    exact = [row for row in tagged if row.get("request_uuid") == uuid]
    if len(exact) != 1:
        return None, [f"expected one exact Caddy row, found {len(exact)}"]
    row = exact[0]
    request = row["request"]
    if request.get("method") != "GET":
        errors.append("Caddy request method is not GET")
    try:
        if int(row.get("status", 0)) != 200:
            errors.append("Caddy response status is not 200")
    except (TypeError, ValueError):
        errors.append("Caddy response status is invalid")
    comparisons = {
        "run_id": run_id,
        "request_uuid": row.get("request_uuid"),
        "remote_ip": request.get("remote_ip"),
        "remote_port": str(request.get("remote_port", "")),
        "http_protocol": request.get("proto"),
        "request_uri": expected_uri,
    }
    for field, expected in comparisons.items():
        if str(response.get(field, "")) != str(expected):
            errors.append(f"response.{field} does not match Caddy")
    if str(response.get("request_host", "")).split(":", 1)[0] != str(request.get("host", "")).split(":", 1)[0]:
        errors.append("response.request_host does not match Caddy")
    try:
        if abs(float(response["server_unix_ms"]) - float(row["ts"]) * 1000) > 2000:
            errors.append("response server time differs from Caddy by more than 2 seconds")
    except (KeyError, TypeError, ValueError, OverflowError):
        errors.append("response.server_unix_ms is missing or invalid")
    if errors:
        return None, errors
    return row, []


def response_evidence_is_preserved(
    response: dict[str, Any],
    selected: dict[str, Any] | None,
    exact_pairing_errors: Sequence[str],
) -> bool:
    """Whether response/Caddy evidence is preserved before later evidence checks."""

    return bool(response) and selected is not None and not exact_pairing_errors


def server_flow_evidence(
    packets: Sequence[dict[str, Any]], caddy_row: dict[str, Any], server_private_ip: str,
    start: dt.datetime, end: dt.datetime,
) -> dict[str, Any]:
    """Match fresh server transport evidence to the exact Caddy five-tuple."""

    request = caddy_row["request"]
    proto = str(request.get("proto", ""))
    transport = "udp" if proto == "HTTP/3.0" else "tcp"
    remote_ip = _ipv4(request.get("remote_ip"), "Caddy remote IP")
    remote_port = int(request.get("remote_port"))
    private_ip = _ipv4(server_private_ip, "server private IPv4")
    setups = []
    for packet in packets:
        timestamp = packet.get("time_epoch")
        if timestamp is None:
            continue
        observed = dt.datetime.fromtimestamp(float(timestamp), tz=dt.timezone.utc)
        exact_tuple = (
            packet.get("src_ip") == remote_ip
            and packet.get("dst_ip") == private_ip
            and packet.get("src_port") == remote_port
            and packet.get("dst_port") == 443
            and packet.get("transport") == transport
        )
        fresh_setup = (
            packet.get("quic_initial") and packet.get("quic_dcid")
            if transport == "udp"
            else packet.get("tcp_syn") and not packet.get("tcp_ack")
        )
        if exact_tuple and fresh_setup:
            setups.append((observed, packet))
    setups.sort(key=lambda item: (item[0], item[1].get("frame_number") or 0))
    caddy_time = dt.datetime.fromtimestamp(float(caddy_row["ts"]), tz=dt.timezone.utc)
    pre_delivery = [item for item in setups if item[0] <= caddy_time]
    earliest = setups[0][0] if setups else None
    connection_ids = sorted(
        {
            str(packet.get("quic_dcid"))
            for _, packet in pre_delivery
            if transport == "udp" and packet.get("quic_dcid")
        }
    )
    # QUIC Retry and ordinary Initial DCID evolution can produce multiple
    # DCIDs on one exact five-tuple; the frozen campaign treats that tuple as
    # one connection identity. Preserve the DCIDs without inventing ambiguity.
    ambiguous = False
    fresh = bool(
        earliest is not None
        and start <= earliest <= caddy_time <= end
        and not ambiguous
    )
    return {
        "transport": "udp_quic_initial" if transport == "udp" and fresh else "tcp_syn" if transport == "tcp" and fresh else "none",
        "fresh": fresh,
        "ambiguous": ambiguous,
        "connection_ids": connection_ids,
        "earliest_setup_utc": earliest.isoformat().replace("+00:00", "Z") if earliest else None,
        "frames": [packet.get("frame_number") for _, packet in pre_delivery],
        "artifacts": sorted({(packet.get("artifact"), packet.get("artifact_sha256")) for _, packet in setups}),
    }


def _packet_counter(value: Any) -> int | None:
    """Extract one unambiguous PF packet counter from structured or text snapshots."""

    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        matches = [int(item) for item in re.findall(r"(?i)\bpackets?\s*[:=]\s*(\d+)", value)]
        return matches[0] if matches and len(set(matches)) == 1 else None
    if isinstance(value, dict):
        direct = [_integer(item) for key, item in value.items() if str(key).lower() in {"packets", "packet_count", "packets_total"}]
        direct = [item for item in direct if item is not None]
        if direct:
            return direct[0] if len(set(direct)) == 1 else None
        nested = [_packet_counter(item) for item in value.values()]
        nested = [item for item in nested if item is not None]
        return nested[0] if nested and len(set(nested)) == 1 else None
    if isinstance(value, list):
        nested = [_packet_counter(item) for item in value]
        nested = [item for item in nested if item is not None]
        return nested[0] if nested and len(set(nested)) == 1 else None
    return None


def pf_counter_result(
    firewall: dict[str, Any], intended_ip: str, condition: str, interface: str
) -> dict[str, Any]:
    rule = str(firewall.get("exact_rule", "")).strip()
    before = _packet_counter(firewall.get("statistics_after_load"))
    after = _packet_counter(firewall.get("statistics_before_cleanup"))
    delta = after - before if before is not None and after is not None and after >= before else None
    intended = _ipv4(intended_ip, "intended ingress")
    expected = (
        f"block drop out quick on {interface} inet proto udp from any to {intended} "
        'port = 443 label "icpr-protocol-diagnostic-v1-udp-block"'
    )
    loaded = str(firewall.get("loaded_rules_snapshot", "")).strip()
    loaded_lines = [line.strip() for line in loaded.splitlines() if line.strip()]
    loaded_exact = len(loaded_lines) == 1 and all(
        fragment in loaded_lines[0]
        for fragment in (
            "block drop out quick",
            f"on {interface}",
            "inet proto udp",
            f"to {intended}",
            "port = 443",
            'label "icpr-protocol-diagnostic-v1-udp-block"',
        )
    )
    exact_rule = rule == expected
    common = bool(
        firewall.get("anchor") == "com.apple/icpr-protocol-diagnostic-v1"
        and firewall.get("condition") == condition
        and not str(firewall.get("previous_anchor_rules", "")).strip()
        and firewall.get("statistics_after_load_utc")
        and firewall.get("statistics_before_cleanup_utc")
        and firewall.get("restored_utc")
    )
    permitted_chronology = False
    try:
        permitted_times = [
            _utc(firewall[field])
            for field in (
                "prepared_utc",
                "statistics_after_load_utc",
                "statistics_before_cleanup_utc",
                "restored_utc",
            )
        ]
        permitted_chronology = permitted_times == sorted(permitted_times)
    except (KeyError, PairingError):
        permitted_chronology = False
    if condition == "udp_permitted":
        valid = bool(
            common
            and permitted_chronology
            and not rule
            and not loaded
            and firewall.get("rule_loaded") is False
            and before in (None, 0)
            and after in (None, 0)
        )
        return {
            "valid": valid,
            "enforced": False,
            "before": before,
            "after": after,
            "delta": delta,
            "exact_rule": not rule,
            "chronology_valid": permitted_chronology,
        }
    chronology = False
    try:
        times = [
            _utc(firewall[field])
            for field in (
                "prepared_utc",
                "rule_load_started_utc",
                "rule_load_completed_utc",
                "statistics_after_load_utc",
                "targeted_state_reset_utc",
                "statistics_before_cleanup_utc",
                "restored_utc",
            )
        ]
        chronology = times == sorted(times)
    except (KeyError, PairingError):
        chronology = False
    valid = bool(
        common
        and exact_rule
        and loaded_exact
        and firewall.get("rule_loaded") is True
        and chronology
        and delta is not None
    )
    enforced = valid and delta is not None and delta > 0
    return {"valid": valid, "enforced": enforced, "before": before, "after": after, "delta": delta, "exact_rule": exact_rule, "loaded_rule_exact": loaded_exact, "chronology_valid": chronology}


def classify_trial(
    *, condition: str, caddy_row: dict[str, Any] | None, server_flow: dict[str, Any],
    client: dict[str, Any], pf: dict[str, Any], egress_catalogue_match: bool,
    real_ip_match: bool, pairing_errors: Sequence[str], integrity_errors: Sequence[str],
) -> tuple[str, str, list[str]]:
    """Pure conservative classification; ambiguity always defeats a finding."""

    ambiguities = list(integrity_errors) + list(pairing_errors)
    if integrity_errors:
        return "integrity_failure", "excluded_ambiguous", ambiguities
    if pairing_errors:
        return "ambiguous_destination_pairing", "excluded_ambiguous", ambiguities
    if caddy_row is None:
        return "no_destination_observation", "observed_non_supporting", ambiguities
    if real_ip_match:
        return "real_ip_bypass", "safety_stop", ambiguities
    if client.get("direct_origin_contacts"):
        return "direct_origin_contact", "excluded_bypass", ambiguities
    if not egress_catalogue_match:
        return "egress_not_in_same_day_catalogue", "excluded_ambiguous", ambiguities
    proto = str(caddy_row.get("request", {}).get("proto", ""))
    if proto == "HTTP/3.0":
        if not server_flow.get("fresh") or server_flow.get("transport") != "udp_quic_initial":
            return "http3_without_fresh_server_quic", "excluded_ambiguous", ambiguities
        if condition == "udp_blocked":
            if client.get("alternative_udp_failover"):
                return "alternative_quic_ingress_failover", "supports_primary_only", ambiguities
            if pf.get("enforced") and client.get("unambiguous_tcp_fallback"):
                return "outer_tcp_fallback_destination_http3", "supports_strong_fallback", ambiguities
            return "blocked_destination_http3_without_strong_fallback_proof", "supports_primary_only", ambiguities
        return "destination_http3_relayed", "supports_primary", ambiguities
    if proto.startswith("HTTP/"):
        return "destination_http2_or_tcp", "observed_non_supporting", ambiguities
    return "unknown_destination_protocol", "excluded_ambiguous", ambiguities


def classify_h3_required_trial(
    *,
    condition: str,
    caddy_row: dict[str, Any] | None,
    server_flow: dict[str, Any],
    client: dict[str, Any],
    pf: dict[str, Any],
    egress_catalogue_match: bool,
    real_ip_match: bool,
    pairing_errors: Sequence[str],
    integrity_errors: Sequence[str],
    origin_gate_valid: bool,
) -> tuple[str, str, list[str]]:
    ambiguities = list(integrity_errors) + list(pairing_errors)
    if not origin_gate_valid:
        ambiguities.append("origin TCP gate is missing, changed, expired, or unverified")
        return "origin_gate_integrity_failure", "excluded_ambiguous", ambiguities
    if integrity_errors:
        return "integrity_failure", "excluded_ambiguous", ambiguities
    if pairing_errors:
        return "ambiguous_destination_pairing", "excluded_ambiguous", ambiguities
    if caddy_row is None:
        return "no_h3_required_destination_observation", "observed_non_supporting", ambiguities
    if real_ip_match:
        return "real_ip_bypass", "safety_stop", ambiguities
    if client.get("direct_origin_contacts"):
        return "direct_origin_contact", "excluded_bypass", ambiguities
    if not egress_catalogue_match:
        return "egress_not_in_same_day_catalogue", "excluded_ambiguous", ambiguities
    proto = str(caddy_row.get("request", {}).get("proto", ""))
    if proto != "HTTP/3.0":
        if proto.startswith("HTTP/"):
            ambiguities.append("destination TCP protocol observed while origin TCP gate attested active")
            return "origin_gate_protocol_contradiction", "excluded_ambiguous", ambiguities
        return "unknown_destination_protocol", "excluded_ambiguous", ambiguities
    if not server_flow.get("fresh") or server_flow.get("transport") != "udp_quic_initial":
        return "http3_without_fresh_server_quic", "excluded_ambiguous", ambiguities
    if condition == "udp_permitted":
        if client.get("outer_transport") != "udp" or client.get("alternative_udp_failover"):
            return (
                "permitted_without_attributable_outer_udp",
                "observed_non_supporting",
                ambiguities,
            )
        return "destination_h3_required", "supports_h3_required_capability", ambiguities
    if client.get("alternative_udp_failover"):
        return "alternative_udp_ingress_h3_required", "supports_h3_required_capability_only", ambiguities
    if not pf.get("valid") or not pf.get("delta"):
        return "blocked_gate_not_engaged", "unevaluable_strong_endpoint", ambiguities
    if pf.get("enforced") and client.get("unambiguous_tcp_fallback"):
        return (
            "outer_tcp_fallback_destination_h3_required",
            "supports_strong_h3_required_fallback",
            ambiguities,
        )
    return "blocked_udp_engaged_without_outer_tcp", "observed_non_supporting", ambiguities


def verify_live_caddy_prefix(path: Path, artifact_hash: str) -> dict[str, Any] | None:
    try:
        path.resolve().relative_to(LIVE_CADDY_PREFIX_ROOT.resolve())
    except ValueError:
        return None
    provenance_path = path.parent / "snapshot-provenance.json"
    provenance_hash = icprlib.verify_sidecar(provenance_path)
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PairingError(f"live Caddy prefix provenance is unreadable: {provenance_path}: {exc}") from exc
    if not isinstance(provenance, dict):
        raise PairingError(f"live Caddy prefix provenance is not an object: {provenance_path}")
    if (
        provenance.get("schema_version") != 1
        or provenance.get("document_type") != "icpr_live_caddy_prefix_snapshot"
        or provenance.get("status") != "verified"
        or provenance.get("capture_method") != "nonselective_active_log_byte_prefix_v1"
        or provenance.get("source_nonselective_prefix") is not True
        or provenance.get("source_mutated") is not False
        or provenance.get("active_pcap_copied") is not False
    ):
        raise PairingError(f"live Caddy prefix provenance is not a verified read-only prefix: {provenance_path}")
    try:
        relative = str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError as exc:
        raise PairingError(f"live Caddy prefix is outside the repository: {path}") from exc
    if provenance.get("snapshot_path") != relative:
        raise PairingError(f"live Caddy prefix provenance names another artifact: {provenance_path}")
    if provenance.get("snapshot_sha256") != artifact_hash:
        raise PairingError(f"live Caddy prefix provenance hash mismatch: {provenance_path}")
    if provenance.get("prefix_bytes") != path.stat().st_size:
        raise PairingError(f"live Caddy prefix provenance byte-count mismatch: {provenance_path}")
    before = provenance.get("source_stat_before")
    after = provenance.get("source_stat_after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise PairingError(f"live Caddy prefix provenance lacks source stat records: {provenance_path}")
    if before.get("device") != after.get("device") or before.get("inode") != after.get("inode"):
        raise PairingError(f"live Caddy prefix source changed identity during capture: {provenance_path}")
    try:
        prefix_bytes = int(provenance.get("prefix_bytes", -1))
        before_size = int(before.get("size_bytes", -1))
        after_size = int(after.get("size_bytes", -1))
    except (TypeError, ValueError) as exc:
        raise PairingError(f"live Caddy prefix provenance has invalid sizes: {provenance_path}") from exc
    if not before_size <= prefix_bytes <= after_size:
        raise PairingError(f"live Caddy prefix sizes are inconsistent: {provenance_path}")
    return {"path": str(provenance_path), "sha256": provenance_hash, **provenance}


def load_caddy_records(server_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for path in sorted(list(server_root.rglob("*.jsonl")) + list(server_root.rglob("*.jsonl.gz"))):
        if path.name.endswith(".packets.jsonl"):
            continue
        try:
            artifact_hash = icprlib.verify_sidecar(path)
            verify_live_caddy_prefix(path, artifact_hash)
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    row_hash = _sha256_text(line)
                    if row_hash in seen:
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise PairingError(f"Caddy row is not an object: {path}:{number}")
                    seen.add(row_hash)
                    records.append({**row, "_artifact": str(path), "_artifact_sha256": artifact_hash, "_line_number": number, "_row_sha256": row_hash})
        except (icprlib.IcprError, PairingError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append(str(exc))
    return records, errors


_PCAP_START = re.compile(r"_(\d{14})\.(?:pcap|pcapng)$")


def candidate_server_pcaps(server_root: Path, event_time: dt.datetime) -> list[Path]:
    """Select rolling captures whose encoded start is within two hours before the event."""

    selected: list[Path] = []
    for path in sorted(list(server_root.rglob("*.pcap")) + list(server_root.rglob("*.pcapng"))):
        match = _PCAP_START.search(path.name)
        if not match:
            continue
        started = dt.datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
        if dt.timedelta(0) <= event_time - started <= dt.timedelta(hours=2):
            selected.append(path)
    return selected


def _attempt_window(metadata: dict[str, Any], capture: dict[str, Any]) -> tuple[dt.datetime, dt.datetime]:
    start = _utc(metadata.get("safari_launch_requested_utc"))
    end_value = capture.get("stopped_utc") or metadata.get("response_deadline_utc") or metadata.get("timeout_deadline_utc")
    end = _utc(end_value)
    if end < start:
        raise PairingError("attempt evidence window ends before Safari launch")
    return start, end


def verify_reference_snapshot(metadata: dict[str, Any], attempt_dir: Path) -> dict[str, Any]:
    path = _resolve_metadata_path(metadata.get("candidate_snapshot_path", ""), attempt_dir)
    recorded = str(metadata.get("candidate_snapshot_sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", recorded):
        raise PairingError("metadata.candidate_snapshot_sha256 is missing or invalid")
    try:
        actual = icprlib.verify_sidecar(path)
    except icprlib.IcprError as exc:
        raise PairingError(str(exc)) from exc
    if actual != recorded:
        raise PairingError("metadata candidate snapshot hash does not match verified snapshot")
    return {"path": str(path), "sha256": actual}


def read_finished_event(attempt_dir: Path) -> dict[str, Any]:
    path = attempt_dir / "events.jsonl"
    try:
        events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PairingError(f"unable to read finalized lifecycle events: {exc}") from exc
    finished = [event for event in events if event.get("event") == "run_finished"]
    if len(finished) != 1:
        raise PairingError(f"expected one run_finished event, found {len(finished)}")
    return finished[0]


def gate_acceptance_by_lifecycle(
    classification: str,
    acceptance: str,
    ambiguities: Sequence[str],
    *,
    outcome: str,
    condition_changed: bool,
    cleanup_valid: bool,
    deadline_missed: bool,
) -> tuple[str, str, list[str]]:
    """Prevent controller/lifecycle failures from becoming positive findings."""

    notes = list(ambiguities)
    potentially_supportive = outcome in {"success", "alternative_ingress"}
    if outcome == "direct_bypass":
        return "real_ip_bypass", "safety_stop", notes
    if acceptance in {"excluded_ambiguous", "excluded_bypass", "safety_stop"}:
        return classification, acceptance, notes
    if potentially_supportive and not cleanup_valid:
        notes.append("attempt cleanup/restoration evidence is incomplete")
        return "integrity_failure", "excluded_ambiguous", notes
    if condition_changed:
        notes.append("operator or automatic end condition changed")
        return "condition_changed", "excluded_ambiguous", notes
    if deadline_missed or outcome == "timeout":
        return "timeout", "observed_non_supporting", notes
    if outcome == "private_relay_unavailable":
        return outcome, "observed_non_supporting", notes
    if outcome == "multiple_destination_connections":
        return outcome, "excluded_ambiguous", notes
    if outcome == "aborted":
        return outcome, "excluded_aborted", notes
    if outcome == "operator_completion_timeout":
        return outcome, "excluded_operational", notes
    if outcome in {"mechanical_failure", "prepare_error"}:
        return outcome, "excluded_mechanical", notes
    if outcome not in {"success", "alternative_ingress"}:
        notes.append(f"unknown finalized controller outcome: {outcome!r}")
        return "integrity_failure", "excluded_ambiguous", notes
    return classification, acceptance, notes


def validate_origin_gate_evidence(
    attempt_dir: Path, metadata: dict[str, Any], server_private_ip: str
) -> dict[str, Any]:
    expected_private_ipv4 = _ipv4(server_private_ip, "server private IPv4")
    session_id = str(metadata.get("gate_session_id", ""))
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", session_id):
        raise PairingError("metadata lacks a valid origin-gate session ID")
    expected_table = "icpr_h3req_" + session_id.replace("-", "_")
    expected_rule = (
        "ip daddr @blocked_targets tcp dport 443 "
        "counter name tcp443_dropped drop"
    )
    values: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for stage in ("pre", "post"):
        path = attempt_dir / f"origin-gate-{stage}.json"
        try:
            digest = icprlib.verify_sidecar(path)
            value = json.loads(path.read_text(encoding="utf-8"))
        except (icprlib.IcprError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PairingError(f"origin-gate {stage} evidence is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise PairingError(f"origin-gate {stage} evidence is not an object")
        if stage == "pre" and digest != metadata.get("origin_gate_pre_sha256"):
            raise PairingError("origin-gate pre hash differs from metadata")
        if not (
            value.get("session_id") == session_id
            and value.get("table_name") == expected_table
            and value.get("table_count") == 1
            and value.get("chain_count") == 1
            and value.get("set_count") == 1
            and value.get("counter_count") == 1
            and value.get("rule_count") == 1
            and value.get("chain_priority") == -10
            and value.get("chain_policy") == "accept"
            and value.get("target_present") is True
            and value.get("target_ipv4") == expected_private_ipv4
            and type(value.get("remaining_seconds")) is int
            and int(value["remaining_seconds"]) > 0
            and value.get("timer_active") is True
            and value.get("timer_unit")
            == f"icpr-h3req-rollback-{session_id}.timer"
            and value.get("caddy_active") is True
            and value.get("capture_active") is True
            and " ".join(str(value.get("exact_rule", "")).split()) == expected_rule
        ):
            raise PairingError(f"origin-gate {stage} evidence violates the frozen gate")
        values[stage] = value
        hashes[stage] = digest
    if values["post"]["remaining_seconds"] > values["pre"]["remaining_seconds"]:
        raise PairingError("origin-gate remaining lifetime increased within a slot")
    return {
        "valid": True,
        "session_id": session_id,
        "table_name": expected_table,
        "pre_sha256": hashes["pre"],
        "post_sha256": hashes["post"],
        "pre_packets": values["pre"].get("packets"),
        "post_packets": values["post"].get("packets"),
    }


def pair_attempt(attempt_dir: Path, caddy_records: Sequence[dict[str, Any]], server_root: Path, server_private_ip: str) -> dict[str, Any]:
    integrity: list[str] = []
    evidence: dict[str, Any] = {"attempt_dir": str(attempt_dir)}
    try:
        verified = icprlib.verify_attempt(attempt_dir)
        evidence["client_manifest_sha256"] = icprlib.verify_sidecar(attempt_dir / "manifest.sha256")
        evidence["client_artifact_hashes"] = verified
        metadata = json.loads((attempt_dir / "metadata.json").read_text(encoding="utf-8"))
        response = json.loads((attempt_dir / "response.json").read_text(encoding="utf-8")) if (attempt_dir / "response.json").is_file() else {}
        capture = json.loads((attempt_dir / "capture-state.json").read_text(encoding="utf-8"))
        firewall = json.loads((attempt_dir / "firewall-state.json").read_text(encoding="utf-8"))
        dns_pin = json.loads((attempt_dir / "dns-pin-state.json").read_text(encoding="utf-8"))
        finished = read_finished_event(attempt_dir)
        finish_condition = (
            json.loads((attempt_dir / "finish-condition.json").read_text(encoding="utf-8"))
            if (attempt_dir / "finish-condition.json").is_file()
            else {}
        )
        if not all(
            isinstance(item, dict)
            for item in (
                metadata,
                response,
                capture,
                firewall,
                dns_pin,
                finished,
                finish_condition,
            )
        ):
            raise PairingError("attempt JSON artifacts must contain objects")
    except (icprlib.IcprError, PairingError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "slot_id": "", "run_id": attempt_dir.name, "attempt_number": "", "retry_number": "", "condition": "unknown",
            "classification": "integrity_failure", "acceptance": "excluded_ambiguous", "ambiguities": [str(exc)], "evidence": evidence,
        }

    required = (
        "run_id", "slot_id", "condition", "real_public_ipv4", "intended_ingress_ipv4",
        "capture_candidates", "candidate_hostname_map", "origin_public_ipv4",
        "safari_launch_requested_utc", "response_deadline_utc",
        "apple_feed_path", "apple_feed_sha256",
        "candidate_snapshot_path", "candidate_snapshot_sha256",
    )
    missing = [field for field in required if metadata.get(field) in (None, "", [])]
    if missing:
        integrity.append(f"missing metadata fields: {missing}")
    if metadata.get("run_id") != attempt_dir.name:
        integrity.append("attempt directory name does not equal metadata.run_id")
    analysis_family = str(metadata.get("analysis_family", "dual_protocol"))
    origin_gate_valid = analysis_family not in GATED_H3_ANALYSIS_FAMILIES
    if analysis_family in GATED_H3_ANALYSIS_FAMILIES:
        try:
            gate_evidence = validate_origin_gate_evidence(
                attempt_dir, metadata, server_private_ip
            )
            evidence["origin_gate"] = gate_evidence
            origin_gate_valid = True
        except PairingError as exc:
            integrity.append(str(exc))
            origin_gate_valid = False
    outcome = str(finished.get("outcome", ""))
    condition_changed = bool(finished.get("condition_changed"))
    automatic_changes = finish_condition.get("automatic_changes", [])
    if automatic_changes:
        condition_changed = True
    cleanup_valid = bool(
        capture.get("stopped_utc")
        and dns_pin.get("restored_utc")
        and firewall.get("restored_utc")
        and isinstance(automatic_changes, list)
    )
    condition = str(metadata.get("condition", "unknown"))
    if condition not in {"udp_permitted", "udp_blocked"}:
        integrity.append("invalid diagnostic condition")
    intended = str(metadata.get("intended_ingress_ipv4", ""))
    effective = dns_pin.get("effective_lookup", {})
    effective_hostnames = dns_pin.get("effective_hostname_lookups", {})
    ipv6_route = dns_pin.get("ipv6_default_route", {})
    if (
        not isinstance(effective, dict)
        or not isinstance(effective_hostnames, dict)
        or not isinstance(ipv6_route, dict)
    ):
        integrity.append("effective pin or IPv6-bypass evidence has invalid schema")
    elif (
        dns_pin.get("pin_ip") != intended
        or set(effective.get("ipv4", [])) != {intended}
        or (effective.get("ipv6") and not ipv6_route.get("confirmed_absent"))
        or any(
            not isinstance(effective_hostnames.get(hostname), dict)
            or set(effective_hostnames[hostname].get("ipv4", [])) != {intended}
            or (
                effective_hostnames[hostname].get("ipv6")
                and not ipv6_route.get("confirmed_absent")
            )
            for hostname in ("mask.icloud.com", "mask-h2.icloud.com")
        )
    ):
        integrity.append("effective pin or IPv6-bypass evidence is invalid")
    try:
        start, end = _attempt_window(metadata, capture)
        feed_rows, feed_evidence = verify_same_day_feed(metadata, attempt_dir)
        evidence["apple_feed"] = feed_evidence
        evidence["candidate_snapshot"] = verify_reference_snapshot(metadata, attempt_dir)
    except PairingError as exc:
        integrity.append(str(exc))
        start = end = dt.datetime.now(dt.timezone.utc)
        feed_rows = []

    server_delivery_sequence = tagged_caddy_sequence(
        caddy_records, metadata, server_private_ip
    )
    evidence["server_delivery_sequence"] = server_delivery_sequence
    if response:
        selected, exact_pairing_errors = exact_caddy_pair(
            caddy_records, metadata, response
        )
    else:
        selected = None
        exact_pairing_errors = (
            []
            if not server_delivery_sequence
            else [
                "response.json is absent but "
                f"{len(server_delivery_sequence)} tagged Caddy row(s) exist"
            ]
        )
    response_evidence_preserved = response_evidence_is_preserved(
        response, selected, exact_pairing_errors
    )
    pairing_errors = list(exact_pairing_errors)
    deadline_missed = False
    if selected is not None:
        try:
            selected_time = dt.datetime.fromtimestamp(float(selected["ts"]), tz=dt.timezone.utc)
            if not start <= selected_time <= end:
                pairing_errors.append("selected Caddy row falls outside the capture/response window")
            deadline = _utc(metadata.get("response_deadline_utc"))
            deadline_missed = selected_time > deadline
        except (PairingError, KeyError, TypeError, ValueError, OverflowError, OSError):
            pairing_errors.append("selected Caddy timestamp is missing or invalid")
    server_evidence = {"transport": "none", "fresh": False, "frames": [], "artifacts": []}
    if selected is not None:
        try:
            event_time = dt.datetime.fromtimestamp(float(selected["ts"]), tz=dt.timezone.utc)
            pcaps = candidate_server_pcaps(server_root, event_time)
            server_packets: list[dict[str, Any]] = []
            request = selected["request"]
            remote_ip = _ipv4(request.get("remote_ip"), "Caddy remote IP")
            remote_port = int(request.get("remote_port"))
            private_ip = _ipv4(server_private_ip, "server private IP")
            transport = "udp" if request.get("proto") == "HTTP/3.0" else "tcp"
            display = f"ip.src=={remote_ip} && ip.dst=={private_ip} && {transport}.srcport=={remote_port} && {transport}.dstport==443"
            for path in pcaps:
                digest = icprlib.verify_sidecar(path)
                server_packets.extend(tshark_packets(path, digest, display))
            server_evidence = server_flow_evidence(server_packets, selected, server_private_ip, start, end)
            if server_evidence.get("ambiguous"):
                pairing_errors.append(
                    "multiple destination QUIC connection IDs share the selected five-tuple"
                )
            if not pcaps:
                pairing_errors.append("no timestamp-compatible server pcap found")
        except (icprlib.IcprError, PairingError, KeyError, TypeError, ValueError, OSError) as exc:
            pairing_errors.append(f"server pcap evidence failure: {exc}")

    try:
        client_pcap = attempt_dir / "client.pcap"
        client_hash = verified.get("client.pcap")
        if not client_hash:
            raise PairingError("manifest-verified client.pcap is missing")
        packets = tshark_packets(client_pcap, client_hash)
        reset_time = _utc(dns_pin.get("networkserviceproxy_state_cleared_utc"))
        if reset_time > end:
            raise PairingError("NetworkServiceProxy reset occurred after the attempt evidence window")
        if condition == "udp_blocked":
            targeted_reset = _utc(firewall.get("targeted_state_reset_utc"))
            if targeted_reset > reset_time:
                raise PairingError("PF targeted state reset occurred after NetworkServiceProxy reset")
        attribution_end = (
            dt.datetime.fromtimestamp(float(selected["ts"]), tz=dt.timezone.utc)
            if selected is not None
            else end
        )
        client = client_contacts(
            packets,
            metadata.get("capture_candidates", []),
            metadata.get("origin_public_ipv4", ""),
            metadata.get("intended_ingress_ipv4", ""),
            metadata.get("candidate_hostname_map", {}),
            reset_time.timestamp(),
            attribution_end.timestamp(),
        )
    except PairingError as exc:
        integrity.append(str(exc))
        client = {
            "contacts": [],
            "attributable_contacts": [],
            "direct_origin_contacts": [],
            "observed_ingress_ips": [],
            "outer_transport": "none",
            "attributable_tcp": False,
            "unambiguous_tcp_fallback": False,
            "alternative_udp_failover": False,
        }

    try:
        pf = pf_counter_result(
            firewall,
            metadata.get("intended_ingress_ipv4", ""),
            condition,
            str(metadata.get("active_interface", "")),
        )
    except PairingError as exc:
        integrity.append(str(exc))
        pf = {"valid": False, "enforced": False, "before": None, "after": None, "delta": None, "exact_rule": False}
    if condition == "udp_blocked" and not pf.get("valid"):
        integrity.append("blocked PF evidence is invalid or lacks unambiguous counters")
    if condition == "udp_permitted" and not pf.get("valid"):
        integrity.append("permitted PF evidence does not prove an empty diagnostic rule state")

    egress = ""
    http_version = ""
    caddy_evidence: dict[str, Any] = {}
    match = None
    if selected is not None:
        request = selected.get("request", {})
        try:
            egress = _ipv4(request.get("remote_ip"), "observed egress IP")
        except PairingError as exc:
            pairing_errors.append(str(exc))
        http_version = str(request.get("proto", ""))
        match = catalogue_match(egress, feed_rows) if egress and feed_rows else None
        caddy_evidence = {
            "path": selected.get("_artifact"), "artifact_sha256": selected.get("_artifact_sha256"),
            "row_sha256": selected.get("_row_sha256"), "line_number": selected.get("_line_number"),
            "request_uuid": selected.get("request_uuid"),
        }
    real_ip_match = bool(egress and egress == str(metadata.get("real_public_ipv4", "")))
    classifier = (
        classify_h3_required_trial
        if analysis_family in GATED_H3_ANALYSIS_FAMILIES
        else classify_trial
    )
    classifier_arguments: dict[str, Any] = {
        "condition": condition,
        "caddy_row": selected,
        "server_flow": server_evidence,
        "client": client,
        "pf": pf,
        "egress_catalogue_match": match is not None,
        "real_ip_match": real_ip_match,
        "pairing_errors": pairing_errors,
        "integrity_errors": integrity,
    }
    if analysis_family in GATED_H3_ANALYSIS_FAMILIES:
        classifier_arguments["origin_gate_valid"] = origin_gate_valid
    classification, acceptance, ambiguities = classifier(**classifier_arguments)
    classification, acceptance, ambiguities = gate_acceptance_by_lifecycle(
        classification,
        acceptance,
        ambiguities,
        outcome=outcome,
        condition_changed=condition_changed,
        cleanup_valid=cleanup_valid,
        deadline_missed=deadline_missed,
    )
    evidence.update(
        {
            "caddy": caddy_evidence,
            "server_pcaps": server_evidence.get("artifacts", []),
            "run_finished": finished,
            "finish_condition": finish_condition,
            "cleanup_valid": cleanup_valid,
            "deadline_missed": deadline_missed,
        }
    )
    result = {
        "slot_id": metadata.get("slot_id", ""),
        "run_id": metadata.get("run_id", attempt_dir.name),
        "attempt_number": metadata.get("sequence_number", metadata.get("attempt_number", "")),
        "retry_number": metadata.get("retry_number", 1),
        "condition": condition,
        "intended_ingress_ipv4": metadata.get("intended_ingress_ipv4", ""),
        "observed_ingress": client.get("observed_ingress_ips", []),
        "pf_counter_result": pf,
        "outer_transport": client.get("outer_transport", "none"),
        "outer_targets": client.get("contacts", []),
        "server_delivery_sequence": server_delivery_sequence,
        "caddy_http_version": http_version,
        "server_pcap_transport": server_evidence.get("transport", "none"),
        "observed_egress_ipv4": egress,
        "same_day_catalogue_match": {"matched": match is not None, "record": match},
        "direct_bypass": {"real_ip_delivery": real_ip_match, "direct_origin_contacts": client.get("direct_origin_contacts", [])},
        "classification": classification,
        "acceptance": acceptance,
        "ambiguities": ambiguities,
        "evidence": evidence,
    }
    if analysis_family == "h3_response_probe":
        result["response_evidence_preserved"] = response_evidence_preserved
    return result


def summarize(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Count the latest finalized retry per slot, separately by condition."""

    latest: dict[str, dict[str, Any]] = {}
    for result in results:
        slot = str(result.get("slot_id") or result.get("run_id"))
        retry = _integer(result.get("retry_number")) or 0
        if slot not in latest or retry >= (_integer(latest[slot].get("retry_number")) or 0):
            latest[slot] = result
    summary: dict[str, Any] = {"count_basis": "latest_finalized_attempt_per_slot"}
    for condition in ("udp_permitted", "udp_blocked"):
        selected = [row for row in latest.values() if row.get("condition") == condition]
        summary[condition] = {
            "slots": len(selected),
            "attempts_total": sum(1 for row in results if row.get("condition") == condition),
            "acceptance_counts": dict(sorted(Counter(str(row.get("acceptance")) for row in selected).items())),
            "classification_counts": dict(sorted(Counter(str(row.get("classification")) for row in selected).items())),
        }
    return summary


def summarize_h3_required(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize(results)
    latest: dict[str, dict[str, Any]] = {}
    for result in results:
        slot_id = str(result.get("slot_id", ""))
        if re.fullmatch(r"h3-required-v1-[0-9]{3}", slot_id):
            retry = _integer(result.get("retry_number")) or 0
            if slot_id not in latest or retry >= (
                _integer(latest[slot_id].get("retry_number")) or 0
            ):
                latest[slot_id] = result
    expected = {f"h3-required-v1-{index:03d}" for index in range(1, 11)}
    exact_conditions = all(
        latest.get(f"h3-required-v1-{index:03d}", {}).get("condition")
        == ("udp_permitted" if index % 2 else "udp_blocked")
        for index in range(1, 11)
    )
    summary.update(
        {
            "analysis_family": "h3_required",
            "denominator_id": "h3-required-v1",
            "planned_slots": {"udp_permitted": 5, "udp_blocked": 5},
            "planned_total": 10,
            "finalized_slot_count": len(latest),
            "missing_slots": sorted(expected - set(latest)),
            "exact_condition_order": exact_conditions,
            "final_complete": set(latest) == expected and exact_conditions,
        }
    )
    return summary


def summarize_h3_response_probe(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    matching = [
        row for row in results
        if row.get("slot_id") == "h3-response-probe-v1-001"
    ]
    latest = max(
        matching,
        key=lambda row: _integer(row.get("retry_number")) or 0,
        default=None,
    )
    return {
        "analysis_family": "h3_response_probe",
        "disposition": "non_counted_exploratory",
        "denominator_id": None,
        "planned_total": 1,
        "finalized_observation_count": 1 if latest else 0,
        "response_evidence_preserved": bool(
            latest and latest.get("response_evidence_preserved")
        ),
        "classification": latest.get("classification") if latest else None,
        "acceptance": latest.get("acceptance") if latest else None,
        "final_complete": latest is not None,
    }


def _json_cell(value: Any) -> Any:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) if isinstance(value, (dict, list)) else value


def write_outputs(
    results: Sequence[dict[str, Any]],
    derived_root: Path,
    *,
    allowed_derived_root: Path = DEFAULT_DERIVED_ROOT,
    analysis_family: str = "dual_protocol",
) -> dict[str, Path]:
    allowed = allowed_derived_root.resolve()
    resolved = derived_root.resolve()
    if resolved != allowed:
        raise PairingError(
            "canonical protocol diagnostic output requires the exact protocol-diagnostic/derived root"
        )
    derived_root.mkdir(parents=True, exist_ok=True)
    json_path = derived_root / "trial-results.json"
    csv_path = derived_root / "trial-results.csv"
    counts_path = derived_root / "condition-counts.json"
    icprlib.write_json(json_path, {"schema_version": "protocol-diagnostic-pairing-v1", "trials": list(results)})
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow({field: _json_cell(result.get(field, "")) for field in CSV_FIELDS})
    if analysis_family == "h3_required":
        output_summary = summarize_h3_required(results)
    elif analysis_family == "h3_response_probe":
        output_summary = summarize_h3_response_probe(results)
    else:
        output_summary = summarize(results)
    icprlib.write_json(counts_path, output_summary)
    for path in (json_path, csv_path, counts_path):
        icprlib.write_sidecar(path)
    return {"json": json_path, "csv": csv_path, "counts": counts_path}


def run(
    client_root: Path,
    server_root: Path,
    derived_root: Path,
    server_private_ip: str,
    *,
    allowed_client_root: Path = DEFAULT_CLIENT_ROOT,
    allowed_derived_root: Path = DEFAULT_DERIVED_ROOT,
    analysis_family: str = "dual_protocol",
) -> dict[str, Any]:
    if analysis_family not in {"dual_protocol", "h3_required", "h3_response_probe"}:
        raise PairingError(f"unsupported protocol diagnostic analysis family: {analysis_family}")
    client_resolved = client_root.resolve()
    allowed_client = allowed_client_root.resolve()
    if client_resolved != allowed_client:
        raise PairingError(
            "canonical protocol diagnostic pairing requires the exact protocol-diagnostic/client root"
        )
    if server_root.resolve() != DEFAULT_SERVER_ROOT.resolve():
        raise PairingError("protocol diagnostic pairing requires server/recovery-data")
    records, log_errors = load_caddy_records(server_root)
    attempts = sorted({path.parent for path in client_root.rglob("metadata.json")})
    results = [pair_attempt(path, records, server_root, server_private_ip) for path in attempts]
    if log_errors:
        for result in results:
            result.setdefault("ambiguities", []).extend(f"server log integrity: {error}" for error in log_errors)
            result["classification"] = "integrity_failure"
            result["acceptance"] = "excluded_ambiguous"
    outputs = write_outputs(
        results,
        derived_root,
        allowed_derived_root=allowed_derived_root,
        analysis_family=analysis_family,
    )
    if analysis_family == "h3_required":
        output_summary = summarize_h3_required(results)
    elif analysis_family == "h3_response_probe":
        output_summary = summarize_h3_response_probe(results)
    else:
        output_summary = summarize(results)
    return {
        "analysis_family": analysis_family,
        "attempts": len(results),
        "outputs": {name: str(path) for name, path in outputs.items()},
        "summary": output_summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-root", type=Path, default=DEFAULT_CLIENT_ROOT)
    parser.add_argument("--server-root", type=Path, default=DEFAULT_SERVER_ROOT)
    parser.add_argument("--derived-root", type=Path, default=DEFAULT_DERIVED_ROOT)
    parser.add_argument("--server-private-ipv4", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(args.client_root, args.server_root, args.derived_root, _ipv4(args.server_private_ipv4, "server private IPv4"))
    except (PairingError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
