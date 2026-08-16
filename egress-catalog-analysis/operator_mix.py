#!/usr/bin/env python3
"""
Operator mix of an Apple Private Relay egress snapshot.

Pipeline (Path A - offline, dated, reproducible):
  prefix  --pyasn longest-prefix-match-->  origin ASN  --AS-name keyword-->  operator

Inputs (use explicitly dated files appropriate to the research design):
  - egress CSV            : cidr, country, region, city, <empty>
  - pyasn .dat            : prefix -> ASN table, built from a RouteViews RIB
  - AS-names JSON         : "asn" -> "HANDLE - Org Name, CC"

Output: blocks per operator, split IPv4/IPv6. Named CDNs are reported first; everything else
is grouped by AS org name so NEW operators surface by name.

Use --collapse to count contiguous merged blocks instead of raw prefixes.
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import defaultdict

from snapshot_common import (
    BgpContainmentFailure,
    BgpLookupFailure,
    DEFAULT_AS_NAMES,
    DEFAULT_BGP_TABLE,
    DEFAULT_SNAPSHOT,
    lookup_covering_bgp,
    warn_date_mismatches,
)


# Known Apple Private Relay egress CDNs. Matched as case-insensitive substrings
# against the AS name, so all sub-ASNs (e.g. AKAMAI-ASN1, AKAMAI-AS) are caught.
CDN_KEYWORDS = [
    ("akamai", "Akamai"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
]
KNOWN_OPERATORS = {op for _, op in CDN_KEYWORDS}


def org_label(asname):
    """Turn 'CLOUDFLARENET - Cloudflare, Inc., US' into 'Cloudflare, Inc.'."""
    if not asname:
        return None
    body = asname.split(" - ", 1)[1] if " - " in asname else asname
    # drop the trailing ', CC' country code
    if "," in body:
        head, tail = body.rsplit(",", 1)
        if len(tail.strip()) == 2 and tail.strip().isalpha():
            body = head
    return body.strip()


def classify(asname):
    """Map an AS name to a CDN operator, or to its org name if not a known CDN."""
    low = (asname or "").lower()
    for kw, op in CDN_KEYWORDS:
        if kw in low:
            return op
    return org_label(asname) or "(unknown org)"


def main():
    ap = argparse.ArgumentParser(description="Operator mix of Apple Private Relay egress")
    ap.add_argument("csv", nargs="?", default=DEFAULT_SNAPSHOT)
    ap.add_argument("--dat", default=DEFAULT_BGP_TABLE)
    ap.add_argument("--names", default=DEFAULT_AS_NAMES)
    ap.add_argument("--collapse", action="store_true",
                    help="count merged contiguous blocks instead of raw prefixes")
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

    # operator -> family -> list of networks (so we can count raw or collapsed)
    nets = defaultdict(lambda: {4: [], 6: []})
    operator_asns = defaultdict(set)   # operator -> {asns seen} (for transparency)
    total = matched = unrouted = malformed = 0
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
                asn, _ = lookup_covering_bgp(asndb, net)
            except BgpContainmentFailure as exc:
                containment_failures += 1
                op = "(invalid BGP containment)"
                if containment_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            except BgpLookupFailure as exc:
                lookup_failures += 1
                op = "(lookup failure)"
                if lookup_failures <= 5:
                    print(f"WARNING: {exc}", file=sys.stderr)
            else:
                if asn is None:
                    op = "(unrouted)"
                    unrouted += 1
                else:
                    op = classify(asnames.get(str(asn)))
                    operator_asns[op].add(asn)
                    matched += 1
            nets[op][net.version].append(net)

    valid = total - malformed
    if valid == 0:
        sys.exit("No valid CIDR rows found.")

    def count(network_list):
        if not args.collapse:
            return len(network_list)
        return len(list(ipaddress.collapse_addresses(network_list)))

    # build per-operator totals
    table = []
    for op, fam in nets.items():
        v4, v6 = count(fam[4]), count(fam[6])
        table.append((op, v4, v6, v4 + v6))
    tot_all = sum(t[3] for t in table)

    unit = "collapsed blocks" if args.collapse else "raw prefixes"
    print(f"egress CSV : {args.csv}")
    print(f"BGP table  : {args.dat}")
    print(f"unit       : {unit}")
    print(f"rows       : {total:,}   matched: {matched:,}   "
          f"unrouted: {unrouted:,}   malformed: {malformed:,}")
    print(f"lookup failures: {lookup_failures:,}   "
          f"containment failures: {containment_failures:,}")
    print(f"ASN coverage: {matched / valid * 100:.2f}% of valid rows resolved "
          "to a containing BGP prefix and ASN")
    print()

    def row(op, v4, v6, tot):
        return (f"  {op:<28} {v4:>9,} {v6:>9,} {tot:>9,} "
                f"{tot / tot_all * 100:>6.2f}%")

    print("=== KNOWN CDN OPERATORS ===")
    print(f"  {'operator':<28} {'IPv4':>9} {'IPv6':>9} {'total':>9} {'share':>7}")
    cdn_total = 0
    for op in ("Akamai", "Cloudflare", "Fastly"):
        match = next((t for t in table if t[0] == op), (op, 0, 0, 0))
        cdn_total += match[3]
        print(row(*match))
    print(f"  {'-> known CDN subtotal':<28} {'':>9} {'':>9} {cdn_total:>9,} "
          f"{cdn_total / tot_all * 100:>6.2f}%")
    print()

    others = sorted((t for t in table if t[0] not in KNOWN_OPERATORS),
                    key=lambda t: -t[3])
    print(f"=== OTHER OPERATORS - top {args.top} ===")
    print(f"  {'operator':<28} {'IPv4':>9} {'IPv6':>9} {'total':>9} {'share':>7}")
    for t in others[:args.top]:
        print(row(*t))
    if len(others) > args.top:
        rest = sum(t[3] for t in others[args.top:])
        print(f"  {'... (' + str(len(others) - args.top) + ' more)':<28} "
              f"{'':>9} {'':>9} {rest:>9,} {rest / tot_all * 100:>6.2f}%")


if __name__ == "__main__":
    main()
