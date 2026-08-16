#!/usr/bin/env python3
"""
Run churn_diff over a window of dated published-egress snapshots.

Finds egress-YYYY-MM-DD.csv files in a directory, sorts them by date, diffs each
consecutive observed pair, and writes a time-series CSV (one row per family per
snapshot pair) plus a printed summary. ``interval_days`` makes gaps explicit.

Usage: churn_series.py [--dir .] [--out churn_series.csv]
"""

import argparse
import csv
import glob
import os
import re
import sys
from datetime import date as calendar_date

import churn_diff

DATE_RE = re.compile(r"egress-(\d{4}-\d{2}-\d{2})\.csv$")

FIELDS = [
    "date_from", "date_to", "interval_days", "family",
    "added_pfx", "removed_pfx", "added_addrs", "removed_addrs",
    "reassigned_addrs", "reassign_count", "fake_churn_pfx",
]


def find_snapshots(d):
    found = []
    for path in glob.glob(os.path.join(d, "egress-*.csv")):
        m = DATE_RE.search(os.path.basename(path))
        if m:
            found.append((m.group(1), path))
    found.sort()
    return found


def observation_interval_days(date_from, date_to):
    """Return the positive calendar-day distance between two snapshot dates."""
    days = (
        calendar_date.fromisoformat(date_to)
        - calendar_date.fromisoformat(date_from)
    ).days
    if days <= 0:
        raise ValueError(f"invalid snapshot interval: {date_from} -> {date_to}")
    return days


def main():
    ap = argparse.ArgumentParser(description="Churn time series over dated snapshots")
    ap.add_argument("--dir", default=".")
    ap.add_argument("--out", default="churn_series.csv")
    args = ap.parse_args()

    snaps = find_snapshots(args.dir)
    if len(snaps) < 2:
        sys.exit(f"need >=2 egress-YYYY-MM-DD.csv files in {args.dir}, found {len(snaps)}")

    print(f"snapshots: {len(snaps)}  ({snaps[0][0]} .. {snaps[-1][0]})")
    rows = []
    # cache loaded snapshots so each file is parsed once
    prev_date, prev_path = snaps[0]
    prev_loaded = churn_diff.load_snapshot(prev_path)

    for date, path in snaps[1:]:
        try:
            interval_days = observation_interval_days(prev_date, date)
        except ValueError as e:
            sys.exit(str(e))
        loaded = churn_diff.load_snapshot(path)
        res = churn_diff.diff(prev_loaded, loaded)
        for fam in (4, 6):
            r = res[fam]
            rows.append({
                "date_from": prev_date, "date_to": date,
                "interval_days": interval_days, "family": f"v{fam}",
                "added_pfx": r["added_pfx"], "removed_pfx": r["removed_pfx"],
                "added_addrs": r["added_addrs"], "removed_addrs": r["removed_addrs"],
                "reassigned_addrs": r["reassigned_addrs"],
                "reassign_count": r["reassign_count"],
                "fake_churn_pfx": r["fake_churn_pfx"],
            })
        # one-line per-pair summary across families
        tot_reassign = sum(res[f]["reassign_count"] for f in (4, 6))
        tot_add = sum(res[f]["added_pfx"] for f in (4, 6))
        tot_rem = sum(res[f]["removed_pfx"] for f in (4, 6))
        tot_fake = sum(res[f]["fake_churn_pfx"] for f in (4, 6))
        flag = "  <-- review location-label changes" if tot_reassign else ""
        interval_note = f" ({interval_days}-day interval)" if interval_days != 1 else ""
        print(f"  {prev_date} -> {date}{interval_note}: +{tot_add} -{tot_rem} pfx, "
              f"{tot_reassign} label-change runs, {tot_fake} re-sliced{flag}")
        prev_date, prev_loaded = date, loaded

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {args.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
