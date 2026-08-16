#!/usr/bin/env python3
"""
Country allocation summary for an Apple Private Relay egress snapshot.

Reads the official Apple egress CSV (no header) with columns:
    cidr, country, region, city, <trailing empty>

Reports a selected country's share by prefix count and, for IPv4, by published
address-space allocation. Address counts are not relay counts or capacity: a
/24 simply covers more published addresses than a /31.
"""

import argparse
import csv
import ipaddress
import sys
from collections import Counter

from snapshot_common import DEFAULT_SNAPSHOT


def analyze(path):
    """Tally prefixes per country, separated by address family.

    Mixing IPv4 and IPv6 address counts is meaningless (one IPv6 /64 dwarfs
    all of IPv4), so we keep them apart. For IPv4 we sum real addresses; for
    IPv6 we count /64 "subnets" as the comparable unit of allocation.
    """
    stats = {
        "rows": 0,
        "malformed": 0,
        "malformed_examples": [],
        "v4_rows": Counter(),   # IPv4 prefixes per country
        "v6_rows": Counter(),   # IPv6 prefixes per country
        "v4_addr": Counter(),   # IPv4 addresses per country
        "v6_64s": Counter(),    # IPv6 /64 blocks per country
        "rows_all": Counter(),  # all prefixes per country (v4 + v6)
    }

    with open(path, newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            stats["rows"] += 1
            cidr = r[0].strip()
            cc = (r[1].strip() if len(r) > 1 else "") or "??"
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                stats["malformed"] += 1
                if len(stats["malformed_examples"]) < 5:
                    stats["malformed_examples"].append(cidr)
                continue
            stats["rows_all"][cc] += 1
            if net.version == 4:
                stats["v4_rows"][cc] += 1
                stats["v4_addr"][cc] += net.num_addresses
            else:
                stats["v6_rows"][cc] += 1
                # /64 blocks; never less than 1 for a prefix longer than /64
                stats["v6_64s"][cc] += max(1, net.num_addresses >> 64)

    return stats


def main():
    ap = argparse.ArgumentParser(
        description="Country allocation summary for Apple Private Relay egress"
    )
    ap.add_argument("csv", nargs="?", default=DEFAULT_SNAPSHOT)
    ap.add_argument("-n", "--top", type=int, default=10, help="top N countries to list")
    ap.add_argument(
        "--country",
        default="US",
        type=lambda value: value.strip().upper(),
        help="two-letter country code to highlight (default: US)",
    )
    args = ap.parse_args()
    if len(args.country) != 2 or not args.country.isalpha():
        ap.error("--country must be a two-letter country code")

    s = analyze(args.csv)
    rows = s["rows"]
    valid = sum(s["rows_all"].values())

    if valid == 0:
        print("No valid CIDR rows found.", file=sys.stderr)
        sys.exit(1)

    tot_all = sum(s["rows_all"].values())
    tot_v4r = sum(s["v4_rows"].values())
    tot_v6r = sum(s["v6_rows"].values())
    tot_v4a = sum(s["v4_addr"].values())
    tot_v6_64 = sum(s["v6_64s"].values())

    print(f"file:                {args.csv}")
    print(f"data rows:           {rows:,}")
    print(f"valid CIDRs:         {valid:,}")
    print(f"malformed CIDRs:     {s['malformed']:,}")
    for cidr in s["malformed_examples"]:
        print(f"  malformed example: {cidr!r}")
    print(f"distinct countries:  {len(s['rows_all']):,}")
    print(f"IPv4 prefixes:       {tot_v4r:,}  ({tot_v4a:,} addresses)")
    print(f"IPv6 prefixes:       {tot_v6r:,}  ({tot_v6_64:,} /64 blocks)")
    print()

    def pct(n, d):
        return f"{n / d * 100:.2f}%" if d else "n/a"

    selected = args.country
    print(f"=== {selected} SHARE ===")
    print(f"  by prefix count (all):  {s['rows_all'][selected]:,} / {tot_all:,} = {pct(s['rows_all'][selected], tot_all)}")
    print(f"  IPv4 prefixes:          {s['v4_rows'][selected]:,} / {tot_v4r:,} = {pct(s['v4_rows'][selected], tot_v4r)}")
    print(f"  IPv4 addresses:         {s['v4_addr'][selected]:,} / {tot_v4a:,} = {pct(s['v4_addr'][selected], tot_v4a)}")
    print(f"  IPv6 prefixes:          {s['v6_rows'][selected]:,} / {tot_v6r:,} = {pct(s['v6_rows'][selected], tot_v6r)}")
    print()

    print(f"Top {args.top} countries (by total prefix count):")
    print(f"  {'CC':<4} {'pfx(all)':>9} {'all%':>6} {'v4pfx':>8} {'v4 addrs':>14} {'v4a%':>6} {'v6pfx':>7}")
    for cc, c in s["rows_all"].most_common(args.top):
        print(
            f"  {cc:<4} {c:>9,} {pct(c, tot_all):>6} "
            f"{s['v4_rows'][cc]:>8,} {s['v4_addr'][cc]:>14,} {pct(s['v4_addr'][cc], tot_v4a):>6} "
            f"{s['v6_rows'][cc]:>7,}"
        )


if __name__ == "__main__":
    main()
