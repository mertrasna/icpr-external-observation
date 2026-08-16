#!/usr/bin/env python3
"""
Four summary statistics for a single egress snapshot:

  1. selected-country share (all subnets, v4+v6, by prefix count)
  2. Total subnets
  3. Operator set + per-operator share of subnets (Akamai NOT merged -> per ASN)
  4. IPv4 subnets vs IPv4 BGP prefixes (the published-vs-routed granularity gap)

"Subnet" = one CIDR row in Apple's list. Operator attribution and BGP prefixes
come from the dated pyasn join, same artifacts as operator_mix.py / bgp_compare.py.
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter

from snapshot_common import (
    BgpContainmentFailure,
    BgpLookupFailure,
    DEFAULT_AS_NAMES,
    DEFAULT_BGP_TABLE,
    DEFAULT_SNAPSHOT,
    lookup_covering_bgp,
    warn_date_mismatches,
)


def main():
    ap = argparse.ArgumentParser(description="Four summary stats for an egress snapshot")
    ap.add_argument("csv", nargs="?", default=DEFAULT_SNAPSHOT)
    ap.add_argument("--dat", default=DEFAULT_BGP_TABLE)
    ap.add_argument("--names", default=DEFAULT_AS_NAMES)
    ap.add_argument(
        "--country",
        default="US",
        type=lambda value: value.strip().upper(),
        help="two-letter country code to highlight (default: US)",
    )
    args = ap.parse_args()
    if len(args.country) != 2 or not args.country.isalpha():
        ap.error("--country must be a two-letter country code")
    warn_date_mismatches(
        args.csv,
        (("BGP table", args.dat), ("AS-names file", args.names)),
    )

    try:
        import pyasn
    except ImportError:
        sys.exit("pyasn not installed - run: pip install -r requirements.txt")
    asndb = pyasn.pyasn(args.dat)
    asnames = json.load(open(args.names))

    rows = total = us = v4_subnets = 0
    malformed = unrouted = lookup_failures = containment_failures = 0
    per_asn = Counter()              # asn -> subnet count
    v4_bgp = set()                   # distinct IPv4 covering BGP prefixes

    with open(args.csv, newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            rows += 1
            try:
                net = ipaddress.ip_network(r[0].strip(), strict=False)
            except ValueError as exc:
                malformed += 1
                if malformed <= 5:
                    print(
                        f"WARNING: malformed CIDR {r[0].strip()!r}: {exc}",
                        file=sys.stderr,
                    )
                continue
            total += 1
            if len(r) > 1 and r[1].strip().upper() == args.country:
                us += 1
            try:
                asn, bgp = lookup_covering_bgp(asndb, net)
            except BgpContainmentFailure as exc:
                containment_failures += 1
                per_asn["(invalid BGP containment)"] += 1
                bgp = None
                if containment_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            except BgpLookupFailure as exc:
                lookup_failures += 1
                per_asn["(lookup failure)"] += 1
                bgp = None
                if lookup_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            else:
                if asn is None:
                    unrouted += 1
                    per_asn["(unrouted)"] += 1
                else:
                    per_asn[asn] += 1
            if net.version == 4:
                v4_subnets += 1
                if bgp is not None:
                    v4_bgp.add(bgp)

    if total == 0:
        sys.exit("No valid CIDR rows found.")

    def label(asn):
        if isinstance(asn, str):
            return asn
        name = asnames.get(str(asn), f"AS{asn}")
        org = name.split(" - ", 1)[-1].rsplit(",", 1)[0]
        return f"{org} (AS{asn})"

    print(f"snapshot: {args.csv}")
    print(f"input quality: {rows:,} rows; {malformed:,} malformed; "
          f"{unrouted:,} unrouted; {lookup_failures:,} lookup failures; "
          f"{containment_failures:,} containment failures\n")

    print(f"1. {args.country} share (all subnets, v4+v6)")
    print(f"   {us:,} / {total:,} = {us / total * 100:.2f}%\n")

    print("2. Total subnets")
    print(f"   {total:,}\n")

    print("3. Operator set + per-operator share of subnets (Akamai not merged)")
    for asn, c in per_asn.most_common():
        print(f"   {label(asn):<40} {c:>9,}  {c / total * 100:>6.2f}%")
    print()

    print("4. IPv4 subnets vs IPv4 BGP prefixes")
    ratio = v4_subnets / len(v4_bgp) if v4_bgp else float("nan")
    print(f"   IPv4 subnets (published) : {v4_subnets:,}")
    print(f"   IPv4 BGP prefixes (routed): {len(v4_bgp):,}")
    print(f"   ratio                    : {ratio:.1f}x more granular than BGP")


if __name__ == "__main__":
    main()
