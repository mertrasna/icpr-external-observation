#!/usr/bin/env python3
"""Build reproducible audit tables for the complete egress snapshot window.

The outputs complement ``churn_series.csv``:

* ``snapshot_manifest.csv``: hashes, sizes, and observation spacing;
* ``snapshot_series.csv``: catalogue size and integrity metrics by date;
* ``country_series.csv``: per-country IPv4/IPv6 allocation metrics;
* ``operator_series.csv``: raw and collapsed blocks by CDN operator;
* ``bgp_series.csv``: distinct frozen-BGP routes used by each operator;
* ``catalogue_changes.csv``: exact raw CIDR-row additions/removals/label edits;
* ``churn_transitions.csv``: complete address-space label transitions.

Operator and BGP tables use the routing artifacts supplied with `--dat` and
`--names`. They describe attribution under that declared control, not live BGP.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
from collections import Counter, defaultdict
from datetime import date as calendar_date

import churn_diff
import churn_series
from operator_mix import classify
from snapshot_common import lookup_covering_bgp


MANIFEST_FIELDS = [
    "date", "days_since_previous", "path", "bytes", "sha256",
]
SNAPSHOT_FIELDS = [
    "date", "rows", "ipv4_prefixes", "ipv6_prefixes", "ipv4_addresses",
    "ipv6_64_blocks", "countries", "locations", "collapsed_ipv4_blocks",
    "collapsed_ipv6_blocks", "noncanonical_cidrs",
]
COUNTRY_FIELDS = [
    "date", "country", "ipv4_prefixes", "ipv4_addresses",
    "ipv6_prefixes", "ipv6_64_blocks", "total_prefixes",
]
OPERATOR_FIELDS = [
    "date", "operator", "ipv4_prefixes", "ipv6_prefixes", "total_prefixes",
    "share_percent", "collapsed_ipv4_blocks", "collapsed_ipv6_blocks",
    "collapsed_total_blocks",
]
BGP_FIELDS = [
    "date", "operator", "ipv4_bgp_prefixes", "ipv6_bgp_prefixes",
    "total_bgp_prefixes",
]
CHANGE_FIELDS = [
    "date_from", "date_to", "interval_days", "family", "change_kind",
    "cidr", "country", "region", "city",
]
TRANSITION_FIELDS = [
    "date_from", "date_to", "interval_days", "family", "from_country",
    "from_region", "from_city", "to_country", "to_region", "to_city",
    "contiguous_runs", "addresses",
]


def _write(path, fields, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {path} ({len(rows):,} rows)")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_snapshot(path):
    """Read and strictly validate one Apple CSV."""
    records = {}
    networks = {4: [], 6: []}
    country = defaultdict(lambda: Counter({
        "ipv4_prefixes": 0,
        "ipv4_addresses": 0,
        "ipv6_prefixes": 0,
        "ipv6_64_blocks": 0,
    }))
    locations = set()
    noncanonical = 0

    with open(path, newline="") as f:
        for line_number, row in enumerate(csv.reader(f), 1):
            if len(row) != 5 or row[4] != "":
                raise ValueError(
                    f"{path}:{line_number}: expected five columns with an empty fifth"
                )
            original = row[0].strip()
            try:
                net = ipaddress.ip_network(original, strict=False)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: malformed CIDR: {exc}") from exc
            canonical = str(net)
            if canonical != original:
                noncanonical += 1
            if canonical in records:
                raise ValueError(f"{path}:{line_number}: duplicate CIDR {canonical}")

            loc = tuple(value.strip() for value in row[1:4])
            records[canonical] = (net.version, loc)
            networks[net.version].append(net)
            locations.add(loc)
            cc = loc[0] or "??"
            if net.version == 4:
                country[cc]["ipv4_prefixes"] += 1
                country[cc]["ipv4_addresses"] += net.num_addresses
            else:
                if net.prefixlen > 64:
                    raise ValueError(
                        f"{path}:{line_number}: IPv6 prefix longer than /64: {canonical}"
                    )
                country[cc]["ipv6_prefixes"] += 1
                country[cc]["ipv6_64_blocks"] += 1 << (64 - net.prefixlen)

    for family in (4, 6):
        networks[family].sort(key=lambda n: int(n.network_address))
        previous = None
        for net in networks[family]:
            if previous is not None and int(net.network_address) <= int(previous.broadcast_address):
                raise ValueError(f"{path}: overlapping CIDRs {previous} and {net}")
            previous = net
    return records, networks, country, locations, noncanonical


def _transition_counts(old_loaded, new_loaded, family):
    """Return transition -> (contiguous runs, addresses)."""
    old_intervals = old_loaded[0][family]
    new_intervals = new_loaded[0][family]
    old_at = churn_diff._locator(old_intervals)
    new_at = churn_diff._locator(new_intervals)
    edges = churn_diff._boundaries(old_intervals, new_intervals)
    segments = []
    address_counts = Counter()
    for start, stop in zip(edges, edges[1:]):
        before = old_at(start)
        after = new_at(start)
        if before is not None and after is not None and before != after:
            transition = (before, after)
            segments.append((start, stop - 1, transition))
            address_counts[transition] += stop - start

    run_counts = Counter()
    previous_end = None
    previous_transition = None
    for start, end, transition in segments:
        if start != (previous_end + 1 if previous_end is not None else None) or transition != previous_transition:
            run_counts[transition] += 1
        previous_end = end
        previous_transition = transition
    return {key: (run_counts[key], addresses) for key, addresses in address_counts.items()}


def main():
    parser = argparse.ArgumentParser(description="Build complete egress-catalogue audit tables")
    parser.add_argument("--dir", default="snapshots")
    parser.add_argument("--dat", default="data/ipasn.dat")
    parser.add_argument("--names", default="data/asnames.json")
    parser.add_argument("--output-dir", default=".")
    args = parser.parse_args()

    snapshots = churn_series.find_snapshots(args.dir)
    if len(snapshots) < 2:
        raise SystemExit(f"need at least two snapshots in {args.dir}")

    try:
        import pyasn
    except ImportError as exc:
        raise SystemExit("pyasn not installed; use .venv/bin/python") from exc
    asndb = pyasn.pyasn(args.dat)
    with open(args.names) as f:
        asnames = json.load(f)

    manifest_rows = []
    snapshot_rows = []
    country_rows = []
    operator_rows = []
    bgp_rows = []
    change_rows = []
    transition_rows = []
    attribution_cache = {}

    previous_date = None
    previous_records = None
    previous_loaded = None

    for date, path in snapshots:
        records, networks, countries, locations, noncanonical = _read_snapshot(path)
        loaded = churn_diff.load_snapshot(path)
        days = "" if previous_date is None else (
            calendar_date.fromisoformat(date) - calendar_date.fromisoformat(previous_date)
        ).days
        manifest_rows.append({
            "date": date,
            "days_since_previous": days,
            "path": os.path.relpath(path),
            "bytes": os.path.getsize(path),
            "sha256": _sha256(path),
        })
        v4_count = len(networks[4])
        v6_count = len(networks[6])
        snapshot_rows.append({
            "date": date,
            "rows": v4_count + v6_count,
            "ipv4_prefixes": v4_count,
            "ipv6_prefixes": v6_count,
            "ipv4_addresses": sum(net.num_addresses for net in networks[4]),
            "ipv6_64_blocks": sum(1 << (64 - net.prefixlen) for net in networks[6]),
            "countries": len(countries),
            "locations": len(locations),
            "collapsed_ipv4_blocks": len(list(ipaddress.collapse_addresses(networks[4]))),
            "collapsed_ipv6_blocks": len(list(ipaddress.collapse_addresses(networks[6]))),
            "noncanonical_cidrs": noncanonical,
        })
        for cc in sorted(countries):
            counts = countries[cc]
            country_rows.append({
                "date": date,
                "country": cc,
                **counts,
                "total_prefixes": counts["ipv4_prefixes"] + counts["ipv6_prefixes"],
            })

        # Frozen-BGP attribution, cached because almost all CIDRs repeat daily.
        op_networks = defaultdict(lambda: {4: [], 6: []})
        bgp_used = defaultdict(lambda: {4: set(), 6: set()})
        for cidr, (family, _loc) in records.items():
            if cidr not in attribution_cache:
                net = ipaddress.ip_network(cidr)
                asn, bgp_prefix = lookup_covering_bgp(asndb, net)
                operator = classify(asnames.get(str(asn))) if asn is not None else "(unrouted)"
                attribution_cache[cidr] = (operator, bgp_prefix)
            operator, bgp_prefix = attribution_cache[cidr]
            op_networks[operator][family].append(ipaddress.ip_network(cidr))
            if bgp_prefix is not None:
                bgp_used[operator][family].add(bgp_prefix)
        total_prefixes = len(records)
        for operator in sorted(op_networks):
            v4 = len(op_networks[operator][4])
            v6 = len(op_networks[operator][6])
            collapsed_v4 = len(list(ipaddress.collapse_addresses(op_networks[operator][4])))
            collapsed_v6 = len(list(ipaddress.collapse_addresses(op_networks[operator][6])))
            operator_rows.append({
                "date": date,
                "operator": operator,
                "ipv4_prefixes": v4,
                "ipv6_prefixes": v6,
                "total_prefixes": v4 + v6,
                "share_percent": f"{(v4 + v6) / total_prefixes * 100:.6f}",
                "collapsed_ipv4_blocks": collapsed_v4,
                "collapsed_ipv6_blocks": collapsed_v6,
                "collapsed_total_blocks": collapsed_v4 + collapsed_v6,
            })
            bgp_rows.append({
                "date": date,
                "operator": operator,
                "ipv4_bgp_prefixes": len(bgp_used[operator][4]),
                "ipv6_bgp_prefixes": len(bgp_used[operator][6]),
                "total_bgp_prefixes": len(bgp_used[operator][4]) + len(bgp_used[operator][6]),
            })

        if previous_records is not None:
            interval_days = int(days)
            old_keys = set(previous_records)
            new_keys = set(records)
            for cidr in sorted(old_keys | new_keys, key=lambda value: (
                ipaddress.ip_network(value).version,
                int(ipaddress.ip_network(value).network_address),
                ipaddress.ip_network(value).prefixlen,
            )):
                old = previous_records.get(cidr)
                new = records.get(cidr)
                events = []
                if old is None:
                    events.append(("added", new))
                elif new is None:
                    events.append(("removed", old))
                elif old[1] != new[1]:
                    events.extend((("label_before", old), ("label_after", new)))
                for kind, (family, loc) in events:
                    change_rows.append({
                        "date_from": previous_date,
                        "date_to": date,
                        "interval_days": interval_days,
                        "family": f"v{family}",
                        "change_kind": kind,
                        "cidr": cidr,
                        "country": loc[0],
                        "region": loc[1],
                        "city": loc[2],
                    })
            for family in (4, 6):
                transitions = _transition_counts(previous_loaded, loaded, family)
                for (before, after), (runs, addresses) in sorted(
                    transitions.items(), key=lambda item: (-item[1][1], item[0])
                ):
                    transition_rows.append({
                        "date_from": previous_date,
                        "date_to": date,
                        "interval_days": interval_days,
                        "family": f"v{family}",
                        "from_country": before[0],
                        "from_region": before[1],
                        "from_city": before[2],
                        "to_country": after[0],
                        "to_region": after[1],
                        "to_city": after[2],
                        "contiguous_runs": runs,
                        "addresses": addresses,
                    })

        previous_date = date
        previous_records = records
        previous_loaded = loaded

    outputs = [
        ("snapshot_manifest.csv", MANIFEST_FIELDS, manifest_rows),
        ("snapshot_series.csv", SNAPSHOT_FIELDS, snapshot_rows),
        ("country_series.csv", COUNTRY_FIELDS, country_rows),
        ("operator_series.csv", OPERATOR_FIELDS, operator_rows),
        ("bgp_series.csv", BGP_FIELDS, bgp_rows),
        ("catalogue_changes.csv", CHANGE_FIELDS, change_rows),
        ("churn_transitions.csv", TRANSITION_FIELDS, transition_rows),
    ]
    os.makedirs(args.output_dir, exist_ok=True)
    for filename, fields, rows in outputs:
        _write(os.path.join(args.output_dir, filename), fields, rows)


if __name__ == "__main__":
    main()
