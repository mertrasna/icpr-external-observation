#!/usr/bin/env python3
"""
Churn diff between two Apple Private Relay published-egress snapshots.

Canonicalizes each daily CSV to disjoint integer address intervals (per family)
labelled with their published (country, region, city), then walks the elementary
segments of the two days together to classify every piece of address space as:

    ADDED       space in D2 not in D1
    REMOVED     space in D1 not in D2
    REASSIGNED  space in both, but its published location label changed
    UNCHANGED   space in both, same location                  (absorbs split/merge)

Because the comparison is at the address level, split/merge re-slicing produces
no add/remove/reassign noise on its own. Split/merge ("fake churn") is reported
separately when changed CIDR rows preserve exactly the same address coverage.
Location-label changes require interpretation: a spelling or city-name update
is not automatically evidence that infrastructure moved.

Within a single daily file prefixes are expected to be non-overlapping, so
intervals are disjoint; we re-check defensively while loading.
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter


def load_snapshot(path):
    """Return {family: [(start, end, loc), ...] sorted disjoint} and
    {family: set(canonical_cidr_str)}. loc is (country, region, city)."""
    intervals = {4: [], 6: []}
    cidrs = {4: set(), 6: set()}
    with open(path, newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            cidr = r[0].strip()
            net = ipaddress.ip_network(cidr, strict=False)
            loc = (
                (r[1].strip() if len(r) > 1 else ""),
                (r[2].strip() if len(r) > 2 else ""),
                (r[3].strip() if len(r) > 3 else ""),
            )
            start = int(net.network_address)
            end = int(net.broadcast_address)
            intervals[net.version].append((start, end, loc))
            # Use the canonical network spelling for raw-CIDR comparisons.
            # Equivalent IPv6 spellings or host-bit input must not create churn.
            cidrs[net.version].add(str(net))

    for fam in (4, 6):
        intervals[fam].sort()
        # defensive disjointness check
        prev_end = None
        for s, e, _ in intervals[fam]:
            if prev_end is not None and s <= prev_end:
                raise ValueError(
                    f"{path}: overlapping intervals in IPv{fam} "
                    f"(start {s} <= previous end {prev_end})"
                )
            prev_end = e
    return intervals, cidrs


def _boundaries(iv1, iv2):
    """Sorted unique segment edges from two disjoint interval lists.

    Each interval [s, e] contributes edges s and e+1 so adjacent/abutting
    intervals split cleanly into half-open [a, b) segments."""
    edges = set()
    for s, e, _ in iv1:
        edges.add(s)
        edges.add(e + 1)
    for s, e, _ in iv2:
        edges.add(s)
        edges.add(e + 1)
    return sorted(edges)


def _locator(intervals):
    """Return a function mapping an address -> loc (or None) via binary search."""
    import bisect

    starts = [s for s, _, _ in intervals]

    def loc_at(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e, loc = intervals[i]
        return loc if s <= addr <= e else None

    return loc_at


def _ranges_to_prefix_count(ranges, family):
    """Count CIDR prefixes needed to cover a list of (start, end) integer ranges."""
    cls = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    n = 0
    for s, e in ranges:
        n += len(list(ipaddress.summarize_address_range(cls(s), cls(e))))
    return n


def _resliced_prefix_count(cidrs1, cidrs2):
    """Count changed CIDR rows that form pure coverage-preserving re-slices.

    Changed old/new prefixes are joined into overlap-connected components. A
    component is cosmetic only when it contains prefixes from both snapshots
    and their collapsed address coverage is exactly identical. This detects
    /22 <-> four /24 changes while avoiding the old subtraction formula,
    which could become negative for partial expansions such as /32 -> /24.
    """
    old = sorted(
        (ipaddress.ip_network(c) for c in cidrs1 - cidrs2),
        key=lambda n: (int(n.network_address), int(n.broadcast_address)),
    )
    new = sorted(
        (ipaddress.ip_network(c) for c in cidrs2 - cidrs1),
        key=lambda n: (int(n.network_address), int(n.broadcast_address)),
    )
    total = len(old) + len(new)
    if not old or not new:
        return 0

    parent = list(range(total))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Prefixes are disjoint within each snapshot, so a two-pointer overlap walk
    # finds every old/new edge without an O(n^2) comparison.
    i = j = 0
    while i < len(old) and j < len(new):
        o, n = old[i], new[j]
        o_start, o_end = int(o.network_address), int(o.broadcast_address)
        n_start, n_end = int(n.network_address), int(n.broadcast_address)
        if o_end < n_start:
            i += 1
            continue
        if n_end < o_start:
            j += 1
            continue
        union(i, len(old) + j)
        if o_end <= n_end:
            i += 1
        if n_end <= o_end:
            j += 1

    components = {}
    for idx, net in enumerate(old + new):
        components.setdefault(find(idx), []).append((idx < len(old), net))

    resliced = 0
    for members in components.values():
        old_members = [net for is_old, net in members if is_old]
        new_members = [net for is_old, net in members if not is_old]
        if not old_members or not new_members:
            continue
        old_coverage = list(ipaddress.collapse_addresses(old_members))
        new_coverage = list(ipaddress.collapse_addresses(new_members))
        if old_coverage == new_coverage:
            resliced += len(members)
    return resliced


def diff(d1, d2):
    """Compare two loaded snapshots. Returns a per-family result dict."""
    iv1_all, cidrs1 = d1
    iv2_all, cidrs2 = d2
    result = {}

    for fam in (4, 6):
        iv1, iv2 = iv1_all[fam], iv2_all[fam]
        loc1 = _locator(iv1)
        loc2 = _locator(iv2)
        edges = _boundaries(iv1, iv2)

        added_ranges, removed_ranges = [], []
        reassigned_segments = []  # (start, end, transition) before merging
        transitions = Counter()  # (loc1, loc2) -> addresses

        for a, b in zip(edges, edges[1:]):
            # half-open [a, b); represent inclusive range [a, b-1]
            size = b - a
            if size <= 0:
                continue
            l1 = loc1(a)
            l2 = loc2(a)
            if l1 is None and l2 is None:
                continue
            if l1 is None:
                added_ranges.append((a, b - 1))
            elif l2 is None:
                removed_ranges.append((a, b - 1))
            elif l1 != l2:
                reassigned_segments.append((a, b - 1, (l1, l2)))
                transitions[(l1, l2)] += size

        # merge address-contiguous reassigned segments into runs so a single
        # relocated block re-sliced into N pieces counts once, not N times
        reassigned_addrs = sum(e - s + 1 for s, e, _ in reassigned_segments)
        runs = 0
        prev_end = None
        prev_transition = None
        for s, e, transition in reassigned_segments:
            if (
                prev_end is None
                or s != prev_end + 1
                or transition != prev_transition
            ):
                runs += 1
            prev_end = e
            prev_transition = transition
        reassign_count = runs

        added_addrs = sum(e - s + 1 for s, e in added_ranges)
        removed_addrs = sum(e - s + 1 for s, e in removed_ranges)
        added_pfx = _ranges_to_prefix_count(added_ranges, fam)
        removed_pfx = _ranges_to_prefix_count(removed_ranges, fam)

        # Raw CIDR-string churn remains useful as a diagnostic, but cosmetic
        # re-slicing is counted directly from equal-coverage overlap components.
        naive_raw_churn = len(cidrs1[fam] ^ cidrs2[fam])
        fake_churn = _resliced_prefix_count(cidrs1[fam], cidrs2[fam])

        result[fam] = {
            "added_pfx": added_pfx,
            "removed_pfx": removed_pfx,
            "added_addrs": added_addrs,
            "removed_addrs": removed_addrs,
            "reassigned_addrs": reassigned_addrs,
            "reassign_count": reassign_count,
            "transitions": transitions,
            "naive_raw_churn": naive_raw_churn,
            "fake_churn_pfx": fake_churn,
        }
    return result


def _fmt(res, label_a, label_b):
    lines = [f"churn: {label_a}  ->  {label_b}", ""]
    for fam in (4, 6):
        r = res[fam]
        lines.append(f"IPv{fam}:")
        lines.append(f"  added:      {r['added_pfx']:>7,} prefixes  ({r['added_addrs']:,} addrs)")
        lines.append(f"  removed:    {r['removed_pfx']:>7,} prefixes  ({r['removed_addrs']:,} addrs)")
        lines.append(f"  label changes: {r['reassign_count']:>7,} contiguous runs  "
                     f"({r['reassigned_addrs']:,} addrs)")
        lines.append(f"  re-slicing:    {r['fake_churn_pfx']:>7,} changed CIDR rows  "
                     f"(naive raw churn {r['naive_raw_churn']:,})")
        if r["transitions"]:
            lines.append("  published location-label changes (top 10 by address count):")
            for (l1, l2), n in r["transitions"].most_common(10):
                lines.append(f"      {l1} -> {l2}  ({n:,} addrs)")
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Churn diff between two egress snapshots")
    ap.add_argument("csv_a")
    ap.add_argument("csv_b")
    ap.add_argument("--json", help="write structured result to this path")
    args = ap.parse_args()

    try:
        d1 = load_snapshot(args.csv_a)
        d2 = load_snapshot(args.csv_b)
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")

    res = diff(d1, d2)
    print(_fmt(res, args.csv_a, args.csv_b))

    if args.json:
        serializable = {
            str(fam): {
                k: (
                    {f"{l1}|{l2}": n for (l1, l2), n in v.items()}
                    if k == "transitions" else v
                )
                for k, v in r.items()
            }
            for fam, r in res.items()
        }
        with open(args.json, "w") as f:
            json.dump(serializable, f, indent=2, default=lambda o: list(o))
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
