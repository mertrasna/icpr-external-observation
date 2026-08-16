#!/usr/bin/env python3
"""Diagnostic: are there overlapping/duplicate prefixes in the egress CSV?

For each address family we:
  - count exact duplicate CIDR strings
  - collapse the prefixes (ipaddress.collapse_addresses) and compare the
    naive address sum vs the collapsed (overlap-free) sum.
If the two sums differ, any naive address sum double-counts covered space.
"""

import csv
import ipaddress
import sys
from collections import Counter

from snapshot_common import DEFAULT_SNAPSHOT


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SNAPSHOT

    seen = Counter()
    v4, v6 = [], []
    malformed = []
    with open(path, newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            cidr = r[0].strip()
            seen[cidr] += 1
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                malformed.append((cidr, str(exc)))
                continue
            (v4 if net.version == 4 else v6).append(net)

    print(f"malformed CIDRs: {len(malformed)}")
    for cidr, error in malformed[:5]:
        print(f"    {cidr!r}: {error}")

    dupes = {c: n for c, n in seen.items() if n > 1}
    print(f"exact duplicate CIDR strings: {len(dupes)}  "
          f"(total extra rows: {sum(n-1 for n in dupes.values())})")
    for c, n in list(sorted(dupes.items(), key=lambda x: -x[1]))[:5]:
        print(f"    {c} x{n}")

    overlap = False
    for label, nets in (("IPv4", v4), ("IPv6", v6)):
        naive = sum(n.num_addresses for n in nets)
        collapsed = list(ipaddress.collapse_addresses(nets))
        dedup = sum(n.num_addresses for n in collapsed)
        print(f"\n{label}:")
        print(f"  prefixes (raw):        {len(nets):,}")
        print(f"  prefixes (collapsed):  {len(collapsed):,}")
        print(f"  addresses (naive sum): {naive:,}")
        print(f"  addresses (overlap-free): {dedup:,}")
        if naive != dedup:
            overlap = True
            print(f"  >>> OVERLAP: naive sum over-counts by {naive - dedup:,} "
                  f"({(naive - dedup) / naive * 100:.4f}%)")
        else:
            print("  no overlap detected (naive == collapsed)")

    return 1 if malformed or dupes or overlap else 0


if __name__ == "__main__":
    sys.exit(main())
