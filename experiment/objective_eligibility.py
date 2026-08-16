"""Derive objective-specific eligibility without changing strict pairing results.

The pairing pipeline deliberately applies one conservative disposition to each
attempt.  That disposition is appropriate for claims that require an exact
client-ingress/server-egress pair, but it is too coarse for evidence that is
independent of ingress attribution.  This module projects the immutable pairing
record into separate, explicit eligibility decisions for each objective.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from icprlib import write_csv, write_json, write_sidecar


ELIGIBILITY_SCHEMA_VERSION = "v1"

SERVER_EVIDENCE_BLOCKERS = {
    "E01_NO_SERVER_OBSERVATION",
    "E02_MULTIPLE_SERVER_CONNECTIONS",
    "E03_NO_FRESH_FLOW",
    "E07_CLOCK_OR_LOG_CORRUPTION",
    "E08_CONDITION_CHANGED",
}
OUTER_LEG_BLOCKERS = SERVER_EVIDENCE_BLOCKERS | {
    "E04_WRONG_OR_UNKNOWN_INGRESS",
}
OBJECTIVE_2_BLOCKERS = OUTER_LEG_BLOCKERS | {
    "E05_REAL_IP_AT_DESTINATION",
    "E06_EGRESS_NOT_IN_FEED",
}
OBJECTIVE_3_BLOCKERS = SERVER_EVIDENCE_BLOCKERS | {
    "E05_REAL_IP_AT_DESTINATION",
    "E06_EGRESS_NOT_IN_FEED",
}


def _triggered_codes(record: dict[str, Any]) -> set[str]:
    value = record.get("triggered_exclusions") or []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = [value] if value else []
    if not isinstance(value, list):
        return set()
    return {str(code) for code in value if code}


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes"}


def _structured_present(value: Any) -> bool:
    if isinstance(value, (dict, list)):
        return bool(value)
    if isinstance(value, str):
        if not value.strip():
            return False
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return False
        return isinstance(parsed, (dict, list)) and bool(parsed)
    return False


def _contact_ingress_ips(value: Any) -> set[str]:
    """Return the distinct ingress addresses from the complete contact set."""

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return set()
    if not isinstance(value, list):
        return set()
    return {
        str(contact["ingress_ip"])
        for contact in value
        if isinstance(contact, dict) and contact.get("ingress_ip")
    }


def _decision(missing: list[str], blockers: set[str]) -> tuple[bool, str]:
    reasons = [*missing, *(f"blocked_by_{code}" for code in sorted(blockers))]
    return (not reasons, "eligible" if not reasons else ";".join(reasons))


def _destination_result(
    record: dict[str, Any], eligible: bool, triggered: set[str]
) -> str:
    """Classify only the destination delivery, independent of ingress E04.

    The strict protocol classification intentionally becomes ambiguous for an
    E04 exact-pair failure.  Reusing it here would erase the independently
    observed server protocol, so this label is derived directly from Caddy and
    server-flow evidence after destination eligibility has been established.
    """

    if not eligible:
        return "ineligible"
    protocol = str(record.get("server_http_protocol") or "")
    transport = str(record.get("server_transport") or "")
    if protocol.startswith("HTTP/3") and transport == "udp":
        suffix = "http3"
    elif protocol.startswith("HTTP/2") and transport == "tcp":
        suffix = "http2"
    else:
        suffix = f"{transport or 'unknown'}_delivery"
    if "E05_REAL_IP_AT_DESTINATION" in triggered:
        return f"real_ip_bypass_{suffix}"
    if "E06_EGRESS_NOT_IN_FEED" in triggered:
        return f"non_feed_{suffix}"
    if record.get("private_relay_state") == "off_control":
        return f"direct_{suffix}_control"
    if not _structured_present(record.get("apple_feed_match")):
        return f"feed_unverified_{suffix}"
    if suffix == "http3":
        return "http3_preserved"
    if suffix == "http2":
        return "http2_delivered"
    return suffix


def eligibility_for_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return objective eligibility while preserving the strict disposition.

    E04 is intentionally ignored only for evidence that does not require exact
    ingress attribution: Objective 1's destination leg and Objective 3's Apple
    feed location observation.  It remains a blocker for the outer leg and the
    exact ingress-egress operator comparison in Objective 2.
    """

    triggered = _triggered_codes(record)
    stable = not _boolean(record.get("condition_changed"))
    server_missing = []
    if record.get("client_outcome") != "success":
        server_missing.append("client_outcome_not_success")
    if not stable:
        server_missing.append("condition_changed")
    if _integer(record.get("server_delivery_count")) != 1:
        server_missing.append("server_delivery_count_not_one")
    if _integer(record.get("response_status")) != 200:
        server_missing.append("response_status_not_200")
    for field in (
        "server_time_utc",
        "server_remote_ip",
        "server_remote_port",
        "server_transport",
        "server_http_protocol",
        "server_flow_key",
        "request_uuid",
    ):
        if record.get(field) in (None, ""):
            server_missing.append(f"missing_{field}")
    if not _structured_present(record.get("freshness_evidence")):
        server_missing.append("missing_freshness_evidence")

    destination_eligible, destination_reason = _decision(
        server_missing, triggered & SERVER_EVIDENCE_BLOCKERS
    )
    destination_result = _destination_result(
        record, destination_eligible, triggered
    )

    outer_missing = [] if destination_eligible else ["destination_leg_ineligible"]
    for field in ("observed_ingress_ip", "ingress_transport", "ingress_5tuple"):
        if record.get(field) in (None, ""):
            outer_missing.append(f"missing_{field}")
    if not _structured_present(record.get("client_ingress_candidates")):
        outer_missing.append("missing_client_ingress_candidates")
    outer_eligible, outer_reason = _decision(
        outer_missing, triggered & OUTER_LEG_BLOCKERS
    )

    objective_2_missing = [] if outer_eligible else ["outer_leg_ineligible"]
    if record.get("private_relay_state") != "on":
        objective_2_missing.append("private_relay_not_on")
    for field in (
        "ingress_asn",
        "egress_asn",
        "ingress_operator",
        "egress_operator",
    ):
        if record.get(field) in (None, ""):
            objective_2_missing.append(f"missing_{field}")
    selected_ingress_ip = str(record.get("observed_ingress_ip") or "")
    attribution_ingress_ips = _contact_ingress_ips(
        record.get("client_ingress_attribution_candidates")
        or record.get("client_ingress_candidates")
    )
    if selected_ingress_ip and attribution_ingress_ips != {selected_ingress_ip}:
        if any(
            ingress_ip != selected_ingress_ip
            for ingress_ip in attribution_ingress_ips
        ):
            objective_2_missing.append("ambiguous_attribution_ingress_contact")
        if selected_ingress_ip not in attribution_ingress_ips:
            objective_2_missing.append("selected_ingress_absent_from_attribution_contacts")
    if record.get("same_operator") not in (True, False, "True", "False", "true", "false"):
        objective_2_missing.append("missing_same_operator_result")
    objective_2_eligible, objective_2_reason = _decision(
        objective_2_missing, triggered & OBJECTIVE_2_BLOCKERS
    )

    objective_3_missing = [] if destination_eligible else ["destination_leg_ineligible"]
    if record.get("private_relay_state") != "on":
        objective_3_missing.append("private_relay_not_on")
    for field in (
        "apple_feed_date",
        "apple_feed_hash",
        "matched_prefix",
        "advertised_country",
        "disclosure_class",
    ):
        if record.get(field) in (None, ""):
            objective_3_missing.append(f"missing_{field}")
    if not _structured_present(record.get("apple_feed_match")):
        objective_3_missing.append("missing_apple_feed_match")
    objective_3_eligible, objective_3_reason = _decision(
        objective_3_missing, triggered & OBJECTIVE_3_BLOCKERS
    )
    objective_3_role = (
        "primary_unpinned"
        if record.get("intended_ingress_group") == "unpinned"
        else "supporting_pinned"
    )

    return {
        "schema_version": ELIGIBILITY_SCHEMA_VERSION,
        "run_id": record.get("run_id", ""),
        "campaign": record.get("campaign", ""),
        "observation_date_utc": str(record.get("server_time_utc") or record.get("client_start_utc") or "")[:10],
        "run_mode": record.get("run_mode", ""),
        "session": record.get("session", ""),
        "slot_id": record.get("slot_id", ""),
        "block_id": record.get("block_id", ""),
        "intended_ingress_group": record.get("intended_ingress_group", ""),
        "strict_disposition": record.get("disposition", ""),
        "strict_exclusion_reason": record.get("exclusion_reason", ""),
        "strict_pending_reason": record.get("pending_reason", ""),
        "triggered_exclusions": sorted(triggered),
        "objective_1_destination_eligible": destination_eligible,
        "objective_1_destination_reason": destination_reason,
        "objective_1_destination_result": destination_result,
        "objective_1_outer_leg_eligible": outer_eligible,
        "objective_1_outer_leg_reason": outer_reason,
        "objective_2_exact_pair_eligible": objective_2_eligible,
        "objective_2_exact_pair_reason": objective_2_reason,
        "objective_3_location_eligible": objective_3_eligible,
        "objective_3_location_reason": objective_3_reason,
        "objective_3_analysis_role": objective_3_role,
        "objective_3_primary_eligible": (
            objective_3_eligible and objective_3_role == "primary_unpinned"
        ),
        "server_delivery_count": record.get("server_delivery_count", ""),
        "server_http_protocol": record.get("server_http_protocol", ""),
        "server_remote_ip": record.get("server_remote_ip", ""),
        "apple_feed_date": record.get("apple_feed_date", ""),
        "matched_prefix": record.get("matched_prefix", ""),
        "advertised_country": record.get("advertised_country", ""),
        "advertised_region": record.get("advertised_region", ""),
        "advertised_city": record.get("advertised_city", ""),
        "disclosure_class": record.get("disclosure_class", ""),
        "pin_contact_status": record.get("pin_contact_status", ""),
        "observed_ingress_ip": record.get("observed_ingress_ip", ""),
        "ingress_operator": record.get("ingress_operator", ""),
        "egress_operator": record.get("egress_operator", ""),
        "same_operator": record.get("same_operator", ""),
    }


ELIGIBILITY_FIELDS = list(
    eligibility_for_record(
        {
            "run_id": "schema",
            "condition_changed": True,
            "triggered_exclusions": [],
        }
    ).keys()
)


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    eligibility_fields = (
        "objective_1_destination_eligible",
        "objective_1_outer_leg_eligible",
        "objective_2_exact_pair_eligible",
        "objective_3_location_eligible",
        "objective_3_primary_eligible",
    )

    def counts(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {}
        materialized = list(items)
        for field in eligibility_fields:
            counter = Counter(
                "eligible" if row[field] else "ineligible" for row in materialized
            )
            result[field] = dict(counter)
        return result

    def result_counts(items: Iterable[dict[str, Any]]) -> dict[str, int]:
        return dict(
            Counter(str(row["objective_1_destination_result"]) for row in items)
        )

    days = sorted({str(row["observation_date_utc"]) for row in rows})
    return {
        "document_type": "objective_specific_eligibility_summary",
        "schema_version": ELIGIBILITY_SCHEMA_VERSION,
        "strict_dispositions_are_unchanged": True,
        "e04_policy": {
            "objective_1_destination": "does_not_require_exact_ingress_attribution",
            "objective_1_outer_leg": "ineligible",
            "objective_2_exact_pair": "ineligible",
            "objective_3_location": "does_not_require_exact_ingress_attribution",
        },
        "counts": counts(rows),
        "objective_1_destination_result_counts": result_counts(rows),
        "days": {
            day: {
                "eligibility": counts(
                    row for row in rows if row["observation_date_utc"] == day
                ),
                "objective_1_destination_result_counts": result_counts(
                    row for row in rows if row["observation_date_utc"] == day
                ),
            }
            for day in days
        },
    }


def write_objective_eligibility(
    records: Iterable[dict[str, Any]], derived: Path
) -> dict[str, Path]:
    rows = [eligibility_for_record(record) for record in records]
    csv_path = derived / "objective_eligibility_v1.csv"
    summary_path = derived / "objective_eligibility_summary_v1.json"
    write_csv(csv_path, rows, ELIGIBILITY_FIELDS)
    write_json(summary_path, _summary(rows))
    return {
        "objective_eligibility": csv_path,
        "objective_eligibility_summary": summary_path,
        "objective_eligibility_sha256": write_sidecar(csv_path),
        "objective_eligibility_summary_sha256": write_sidecar(summary_path),
    }
