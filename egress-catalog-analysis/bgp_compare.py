#!/usr/bin/env python3
"""
BGP-prefix count per operator for Apple Private Relay egress.

Where operator_mix.py counts Apple's *published* egress entries, this counts
the distinct *BGP routes* those entries fall inside -- i.e. how many real
announced prefixes back each operator's egress footprint. This is the unit a
BGP-level 2022 study would report.

For every egress entry, pyasn.lookup() returns (origin_ASN, covering_BGP_prefix).
We bucket the covering BGP prefixes into a set per operator (so each routed
prefix is counted once no matter how many egress entries sit in it), split by
address family. As context we also show each operator's total announced BGP
prefixes (`get_as_prefixes`).
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import defaultdict

from operator_mix import classify, KNOWN_OPERATORS  # reuse the AS-name classifier
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
    ap = argparse.ArgumentParser(description="Distinct BGP prefixes per CDN for PR egress")
    ap.add_argument("csv", nargs="?", default=DEFAULT_SNAPSHOT)
    ap.add_argument("--dat", default=DEFAULT_BGP_TABLE)
    ap.add_argument("--names", default=DEFAULT_AS_NAMES)
    ap.add_argument("-n", "--top", type=int, default=15,
                    help="how many non-CDN operators to list")
    args = ap.parse_args()
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

    # operator -> family -> set of covering BGP prefixes used by egress
    bgp_used = defaultdict(lambda: {4: set(), 6: set()})
    operator_asns = defaultdict(set)
    egress_rows = defaultdict(int)   # operator -> count of egress entries
    # per-ASN equivalents (2022 reported Akamai across two ASNs)
    bgp_used_asn = defaultdict(lambda: {4: set(), 6: set()})
    egress_rows_asn = defaultdict(int)
    asn_operator = {}
    total = matched = malformed = unrouted = 0
    lookup_failures = containment_failures = 0

    with open(args.csv, newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            total += 1
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
            try:
                asn, bgp_prefix = lookup_covering_bgp(asndb, net)
            except BgpContainmentFailure as exc:
                containment_failures += 1
                op = "(invalid BGP containment)"
                bgp_prefix = None
                if containment_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            except BgpLookupFailure as exc:
                lookup_failures += 1
                op = "(lookup failure)"
                bgp_prefix = None
                if lookup_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            else:
                if asn is None:
                    op = "(unrouted)"
                    unrouted += 1
                else:
                    op = classify(asnames.get(str(asn)))
                    operator_asns[op].add(asn)
                    asn_operator[asn] = op
                    egress_rows_asn[asn] += 1
                    bgp_used_asn[asn][net.version].add(bgp_prefix)
                    matched += 1
            egress_rows[op] += 1
            if bgp_prefix is not None:
                bgp_used[op][net.version].add(bgp_prefix)

    valid = total - malformed
    if valid == 0:
        sys.exit("No valid CIDR rows found.")

    # total announced BGP footprint per operator (across its ASNs, both families)
    def footprint(asns):
        v4 = v6 = 0
        for a in asns:
            for p in asndb.get_as_prefixes(a) or []:
                if ":" in p:
                    v6 += 1
                else:
                    v4 += 1
        return v4, v6

    def stats(op):
        u4, u6 = len(bgp_used[op][4]), len(bgp_used[op][6])
        f4, f6 = footprint(operator_asns[op])
        return u4, u6, u4 + u6, f4 + f6

    print(f"egress CSV : {args.csv}")
    print(f"BGP table  : {args.dat}")
    print(f"rows       : {total:,}   matched: {matched:,}   "
          f"unrouted: {unrouted:,}   malformed: {malformed:,}")
    print(f"lookup failures: {lookup_failures:,}   "
          f"containment failures: {containment_failures:,}")
    print()
    print("Distinct BGP prefixes the egress maps into, per operator")
    print("(BGP-used = routes containing >=1 egress entry; "
          "footprint = operator's total announced prefixes)")
    print()
    print(f"  {'operator':<28} {'BGP v4':>8} {'BGP v6':>8} {'BGP tot':>8} "
          f"{'egress':>9} {'footprint':>10} {'used%':>7}")

    def row(op):
        u4, u6, utot, ftot = stats(op)
        used_pct = f"{utot / ftot * 100:.1f}%" if ftot else "n/a"
        print(f"  {op:<28} {u4:>8,} {u6:>8,} {utot:>8,} "
              f"{egress_rows[op]:>9,} {ftot:>10,} {used_pct:>7}")

    for op in ("Akamai", "Cloudflare", "Fastly"):
        row(op)

    others = sorted((o for o in egress_rows if o not in KNOWN_OPERATORS),
                    key=lambda o: -stats(o)[2])
    if others:
        print()
        print(f"  --- other operators (top {args.top}) ---")
        for op in others[:args.top]:
            row(op)

    # per-ASN breakdown (matches a 2022 report that split Akamai across two ASNs)
    print()
    print("Per-ASN breakdown (BGP prefixes the egress maps into):")
    print(f"  {'ASN':<10} {'operator':<12} {'BGP v4':>8} {'BGP v6':>8} "
          f"{'BGP tot':>8} {'egress':>9}  AS name")
    for asn in sorted(asn_operator, key=lambda a: -(len(bgp_used_asn[a][4]) + len(bgp_used_asn[a][6]))):
        u4, u6 = len(bgp_used_asn[asn][4]), len(bgp_used_asn[asn][6])
        print(f"  AS{asn:<8} {asn_operator[asn]:<12} {u4:>8,} {u6:>8,} "
              f"{u4 + u6:>8,} {egress_rows_asn[asn]:>9,}  {asnames.get(str(asn), '')}")


if __name__ == "__main__":
    main()
