#!/usr/bin/env python3
"""Synthetic fixture tests for churn_diff. No pytest dependency.

Run: .venv/bin/python tests/test_churn.py

Each case writes two tiny CSV snapshots to a temp dir, diffs them, and asserts
the classification. The key case is `reslice_relocate`: a block that is BOTH
re-sliced and relocated -- the interval method must report the relocation while
a naive CIDR-string diff would hide it as add/remove noise.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import churn_diff  # noqa: E402
import churn_series  # noqa: E402

A = ("US", "US-CA", "CityA")
B = ("US", "US-NY", "CityB")

failures = 0


def write_csv(path, rows):
    with open(path, "w") as f:
        for cidr, loc in rows:
            f.write(f"{cidr},{loc[0]},{loc[1]},{loc[2]},\n")


def run(name, rows1, rows2, checks):
    """checks: dict of family -> dict of field -> expected value."""
    global failures
    with tempfile.TemporaryDirectory() as d:
        p1, p2 = os.path.join(d, "d1.csv"), os.path.join(d, "d2.csv")
        write_csv(p1, rows1)
        write_csv(p2, rows2)
        res = churn_diff.diff(churn_diff.load_snapshot(p1), churn_diff.load_snapshot(p2))
    ok = True
    for fam, fields in checks.items():
        for field, expected in fields.items():
            got = res[fam][field]
            if got != expected:
                ok = False
                print(f"  FAIL {name} IPv{fam} {field}: expected {expected}, got {got}")
    if ok:
        print(f"  ok   {name}")
    else:
        failures += 1
    return res


print("churn_diff fixture tests")

# pure add: one extra /24 appears
run("pure_add",
    [("10.0.0.0/24", A)],
    [("10.0.0.0/24", A), ("10.0.1.0/24", B)],
    {4: {"added_pfx": 1, "added_addrs": 256, "removed_pfx": 0,
         "reassign_count": 0, "fake_churn_pfx": 0}})

# pure remove: a /24 disappears
run("pure_remove",
    [("10.0.0.0/24", A), ("10.0.1.0/24", B)],
    [("10.0.0.0/24", A)],
    {4: {"removed_pfx": 1, "removed_addrs": 256, "added_pfx": 0,
         "reassign_count": 0, "fake_churn_pfx": 0}})

# pure split: /22 -> four /24, same location. zero real churn, fake churn = 5.
run("pure_split",
    [("10.0.0.0/22", A)],
    [("10.0.0.0/24", A), ("10.0.1.0/24", A), ("10.0.2.0/24", A), ("10.0.3.0/24", A)],
    {4: {"added_pfx": 0, "removed_pfx": 0, "reassigned_addrs": 0,
         "fake_churn_pfx": 5}})

# pure merge: reverse of split
run("pure_merge",
    [("10.0.0.0/24", A), ("10.0.1.0/24", A), ("10.0.2.0/24", A), ("10.0.3.0/24", A)],
    [("10.0.0.0/22", A)],
    {4: {"added_pfx": 0, "removed_pfx": 0, "reassigned_addrs": 0,
         "fake_churn_pfx": 5}})

# reassign: /24 keeps its slot but changes claimed location
run("reassign",
    [("10.0.0.0/24", A)],
    [("10.0.0.0/24", B)],
    {4: {"reassign_count": 1, "reassigned_addrs": 256,
         "added_pfx": 0, "removed_pfx": 0, "fake_churn_pfx": 0}})

# reslice + relocate: /22 in A becomes four /24, one of them now in B.
# coverage unchanged, so add/remove = 0; the moved /24 must surface as reassign.
res = run("reslice_relocate",
    [("10.0.0.0/22", A)],
    [("10.0.0.0/24", A), ("10.0.1.0/24", A), ("10.0.2.0/24", B), ("10.0.3.0/24", A)],
    {4: {"added_pfx": 0, "removed_pfx": 0,
         "reassign_count": 1, "reassigned_addrs": 256}})
# verify the transition is recorded A -> B
if res[4]["transitions"].get((A, B)) != 256:
    print(f"  FAIL reslice_relocate transition A->B: got {dict(res[4]['transitions'])}")
    failures += 1

# identical files: everything zero (mirrors the real 06-21 vs 06-22 case)
run("identical",
    [("10.0.0.0/24", A), ("2001:db8::/48", B)],
    [("10.0.0.0/24", A), ("2001:db8::/48", B)],
    {4: {"added_pfx": 0, "removed_pfx": 0, "reassigned_addrs": 0, "fake_churn_pfx": 0},
     6: {"added_pfx": 0, "removed_pfx": 0, "reassigned_addrs": 0, "fake_churn_pfx": 0}})

# IPv6 reassign sanity
run("ipv6_reassign",
    [("2001:db8::/48", A)],
    [("2001:db8::/48", B)],
     {6: {"reassign_count": 1, "reassigned_addrs": 2 ** 80,
          "added_pfx": 0, "removed_pfx": 0}})

# Partial expansion must not produce negative cosmetic churn. The 255 newly
# covered addresses require eight CIDRs when represented exactly.
run("partial_expansion",
    [("10.0.0.0/32", A)],
    [("10.0.0.0/24", A)],
    {4: {"added_pfx": 8, "added_addrs": 255, "removed_pfx": 0,
         "fake_churn_pfx": 0}})

# Two adjacent ranges with different location transitions are two runs.
run("adjacent_distinct_transitions",
    [("10.0.0.0/25", A), ("10.0.0.128/25", B)],
    [("10.0.0.0/25", B), ("10.0.0.128/25", A)],
    {4: {"reassign_count": 2, "reassigned_addrs": 256}})

# A pure re-slice elsewhere must still be detected on a day with a real add.
run("reslice_plus_add",
    [("10.0.0.0/22", A)],
    [("10.0.0.0/24", A), ("10.0.1.0/24", A),
     ("10.0.2.0/24", A), ("10.0.3.0/24", A),
     ("10.0.4.0/24", B)],
    {4: {"added_pfx": 1, "added_addrs": 256, "fake_churn_pfx": 5}})

# Equal-sized but shifted coverage is real add/remove churn, not re-slicing.
run("equal_size_shift",
    [("10.0.0.0/25", A)],
    [("10.0.0.64/26", A), ("10.0.0.128/26", A)],
    {4: {"added_addrs": 64, "removed_addrs": 64, "fake_churn_pfx": 0}})

# Equivalent textual forms canonicalize to the same CIDR.
run("canonical_ipv6_spelling",
    [("2001:0db8:0000:0000::/64", A)],
    [("2001:db8::/64", A)],
    {6: {"added_pfx": 0, "removed_pfx": 0, "fake_churn_pfx": 0}})

# Overlapping rows in one snapshot must be rejected.
with tempfile.TemporaryDirectory() as d:
    overlap = os.path.join(d, "overlap.csv")
    write_csv(overlap, [("10.0.0.0/24", A), ("10.0.0.0/25", A)])
    try:
        churn_diff.load_snapshot(overlap)
    except ValueError:
        print("  ok   overlap_rejected")
    else:
        print("  FAIL overlap_rejected: expected ValueError")
        failures += 1

if churn_series.observation_interval_days("2026-07-05", "2026-07-07") == 2:
    print("  ok   missing_day_interval")
else:
    print("  FAIL missing_day_interval: expected 2 days")
    failures += 1

print()
if failures:
    print(f"{failures} case(s) FAILED")
    sys.exit(1)
print("all cases passed")
