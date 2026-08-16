#!/usr/bin/env python3
"""Validate hash-protected RIPEstat BGP State evidence and append ASN rows."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_ORIGINS = HERE / "origin_prefixes.csv"
DEFAULT_PAIRS = HERE.parent.parent / "derived" / "pairs_v1.csv"
EVIDENCE_NAME = "ripestat-bgp-state-{date}-pending-reconstruction-v1.json"
SOURCE_LABEL = (
    "RIPEstat BGP State API v1.2 historical reconstruction "
    "(RIPE RIS; 00:00,08:00,16:00,23:59:59 UTC)"
)


class EvidenceError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sidecar(path: Path) -> str:
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.is_file():
        raise EvidenceError(f"SHA-256 sidecar is missing: {sidecar}")
    line = sidecar.read_text(encoding="utf-8").strip()
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
    if not match or match.group(2) != path.name:
        raise EvidenceError(f"invalid SHA-256 sidecar: {sidecar}")
    actual = sha256_file(path)
    if match.group(1) != actual:
        raise EvidenceError(f"SHA-256 mismatch: {path}")
    return actual


def parse_utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def normalized_timestamp(value: str) -> str:
    return parse_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def choose_route(response: dict, address: str) -> tuple[str, str]:
    try:
        ip = ipaddress.ip_address(address)
        state = response["data"]["bgp_state"]
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceError(f"invalid BGP State response for {address}: {exc}") from exc
    matches: list[tuple[int, str, list[dict]]] = []
    by_prefix: dict[str, list[dict]] = {}
    for route in state:
        try:
            network = ipaddress.ip_network(str(route["target_prefix"]), strict=False)
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(f"invalid target prefix for {address}: {exc}") from exc
        if network.version == ip.version and ip in network:
            by_prefix.setdefault(str(network), []).append(route)
    for prefix, routes in by_prefix.items():
        matches.append((ipaddress.ip_network(prefix).prefixlen, prefix, routes))
    if not matches:
        raise EvidenceError(f"no RIS route contains {address}")
    longest = max(item[0] for item in matches)
    best = [(prefix, routes) for length, prefix, routes in matches if length == longest]
    if len(best) != 1:
        raise EvidenceError(f"multiple most-specific RIS prefixes contain {address}")
    prefix, routes = best[0]
    origins: set[str] = set()
    for route in routes:
        path = route.get("path")
        if not isinstance(path, list) or not path:
            raise EvidenceError(f"empty or invalid RIS AS path for {address} in {prefix}")
        origin = str(path[-1])
        if not origin.isdigit() or not 1 <= int(origin) <= 4_294_967_295:
            raise EvidenceError(f"non-scalar RIS origin for {address} in {prefix}: {origin}")
        origins.add(origin)
    if len(origins) != 1:
        raise EvidenceError(
            f"multiple RIS origins for {address} in {prefix}: {sorted(origins)}"
        )
    return prefix, next(iter(origins))


def derive_rows(plan: dict, evidence_dir: Path) -> tuple[list[dict[str, str]], list[str]]:
    expected_times = plan["selection_rule"]["timestamps_each_observation_date_utc"]
    derived: list[dict[str, str]] = []
    errors: list[str] = []
    for date, addresses in plan["resources_by_observation_date"].items():
        path = evidence_dir / EVIDENCE_NAME.format(date=date)
        try:
            evidence_hash = verify_sidecar(path)
            evidence = json.loads(path.read_text(encoding="utf-8"))
            if evidence.get("schema_version") != "v1":
                raise EvidenceError("evidence schema_version is not v1")
            if evidence.get("document_type") != "historical_origin_asn_reconstruction_evidence":
                raise EvidenceError("evidence document_type is invalid")
            if evidence.get("observation_date_utc") != date:
                raise EvidenceError("evidence observation date does not match")
            parse_utc(str(evidence.get("queried_utc", "")))
            responses = evidence.get("responses")
            if not isinstance(responses, list) or len(responses) != len(expected_times):
                raise EvidenceError("evidence does not contain every planned timestamp")
            by_time = {item.get("requested_timestamp"): item for item in responses}
            expected_stamps = [f"{date}T{time}" for time in expected_times]
            if set(by_time) != set(expected_stamps):
                raise EvidenceError("evidence timestamps differ from the reconstruction plan")
            per_address: dict[str, list[tuple[str, str]]] = {address: [] for address in addresses}
            for stamp in expected_stamps:
                item = by_time[stamp]
                if sorted(item.get("requested_resources", [])) != sorted(addresses):
                    raise EvidenceError(f"requested resource set differs at {stamp}")
                response = item.get("api_response")
                if not isinstance(response, dict):
                    raise EvidenceError(f"API response is absent at {stamp}")
                if (
                    response.get("status") != "ok"
                    or response.get("status_code") != 200
                    or response.get("data_call_name") != "bgp-state"
                    or response.get("version") != "1.2"
                ):
                    raise EvidenceError(f"RIPEstat BGP State query failed at {stamp}")
                returned_stamp = normalized_timestamp(str(response["data"]["timestamp"]))
                if returned_stamp != normalized_timestamp(stamp):
                    raise EvidenceError(f"RIPEstat timestamp differs at {stamp}")
                for address in addresses:
                    per_address[address].append(choose_route(response, address))
            for address, observations in per_address.items():
                if len(set(observations)) != 1:
                    raise EvidenceError(
                        f"historical prefix/origin changed for {address}: {sorted(set(observations))}"
                    )
                prefix, asn = observations[0]
                derived.append(
                    {
                        "date": date,
                        "prefix": prefix,
                        "asn": asn,
                        "source": SOURCE_LABEL,
                        "source_hash": evidence_hash,
                    }
                )
        except (EvidenceError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            errors.append(f"{date}: {exc}")
    unique = {
        (row["date"], row["prefix"], row["asn"]): row
        for row in derived
    }
    return [unique[key] for key in sorted(unique)], errors


def load_origins(path: Path) -> tuple[list[dict[str, str]], str]:
    digest = verify_sidecar(path)
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["date", "prefix", "asn", "source", "source_hash"]:
            raise EvidenceError(f"unexpected origin CSV schema: {path}")
        return list(reader), digest


def pending_resources(pairs_path: Path, dates: list[str]) -> tuple[dict[str, list[str]], dict[str, int]]:
    resources: dict[str, set[str]] = {date: set() for date in dates}
    counts: dict[str, int] = {date: 0 for date in dates}
    with pairs_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            date = str(row.get("apple_feed_date", ""))
            if date not in resources or row.get("pending_reason") != "dated_asn_mapping_missing":
                continue
            counts[date] += 1
            for field in ("observed_ingress_ip", "server_remote_ip"):
                value = str(row.get(field, "")).strip()
                if value:
                    resources[date].add(str(ipaddress.ip_address(value)))
    return {date: sorted(values) for date, values in resources.items()}, counts


def validate_plan_coverage(plan: dict, pairs_path: Path) -> None:
    dates = list(plan["observation_dates_utc"])
    actual_resources, actual_counts = pending_resources(pairs_path, dates)
    planned_resources = {
        date: sorted(values)
        for date, values in plan["resources_by_observation_date"].items()
    }
    if actual_resources != planned_resources:
        raise EvidenceError(
            "reconstruction plan does not exactly cover the current dated-ASN pending addresses"
        )
    planned_counts = {
        date: int(plan["pending_observation_counts"][date]) for date in dates
    }
    if actual_counts != planned_counts:
        raise EvidenceError(
            "reconstruction plan pending counts differ from the current pair output"
        )


def write_origins(path: Path, rows: list[dict[str, str]]) -> str:
    fields = ["date", "prefix", "asn", "source", "source_hash"]
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        temp_name = handle.name
    os.replace(temp_name, path)
    digest = sha256_file(path)
    sidecar = path.with_name(path.name + ".sha256")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(f"{digest}  {path.name}\n")
        sidecar_temp_name = handle.name
    os.replace(sidecar_temp_name, sidecar)
    path.chmod(0o444)
    sidecar.chmod(0o444)
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, default=HERE)
    parser.add_argument("--origins", type=Path, default=DEFAULT_ORIGINS)
    parser.add_argument("--pairs", type=Path, default=DEFAULT_PAIRS)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    verify_sidecar(args.plan)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    validate_plan_coverage(plan, args.pairs)
    current, old_hash = load_origins(args.origins)
    derived, errors = derive_rows(plan, args.evidence_dir)
    existing = {(row["date"], row["prefix"], row["asn"]) for row in current}
    additions = [
        row for row in derived
        if (row["date"], row["prefix"], row["asn"]) not in existing
    ]
    report = {
        "status": "blocked" if errors else "ready",
        "old_origin_dataset_sha256": old_hash,
        "derived_rows": derived,
        "rows_to_append": additions,
        "errors": errors,
        "applied": False,
    }
    if args.apply:
        if errors:
            raise EvidenceError("refusing to apply incomplete or inconsistent evidence")
        conflicts = {
            (old["date"], old["prefix"])
            for old in current
            for new in additions
            if old["date"] == new["date"]
            and old["prefix"] == new["prefix"]
            and old["asn"] != new["asn"]
        }
        if conflicts:
            raise EvidenceError(f"refusing conflicting origin rows: {sorted(conflicts)}")
        new_hash = write_origins(args.origins, current + additions)
        report.update(applied=True, new_origin_dataset_sha256=new_hash)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
