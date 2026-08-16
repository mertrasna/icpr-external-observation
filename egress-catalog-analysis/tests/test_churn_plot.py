#!/usr/bin/env python3
"""Focused data-loading and plotting tests for churn_plot.

Run: .venv/bin/python tests/test_churn_plot.py
"""

import csv
import hashlib
import os
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import churn_plot  # noqa: E402


FIELDS = [
    "date_from", "date_to", "interval_days", "family", "added_pfx",
    "removed_pfx", "added_addrs", "removed_addrs", "reassigned_addrs",
    "reassign_count", "fake_churn_pfx",
]


def row(date_from, date_to, family, *, added=0, removed=0, labels=0):
    return {
        "date_from": date_from,
        "date_to": date_to,
        "interval_days": str((date.fromisoformat(date_to) - date.fromisoformat(date_from)).days),
        "family": family,
        "added_pfx": str(added),
        "removed_pfx": str(removed),
        "added_addrs": "0",
        "removed_addrs": "0",
        "reassigned_addrs": "0",
        "reassign_count": str(labels),
        "fake_churn_pfx": "0",
    }


def write_series(path, rows):
    with open(path, "w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def labelled_line(axis, label):
    return next(line for line in axis.lines if line.get_label() == label)


def test_arbitrary_series_with_gap_and_all_metrics():
    rows = [
        row("2027-01-01", "2027-01-02", "v4", added=2, removed=1, labels=3),
        row("2027-01-01", "2027-01-02", "v6", added=4, removed=5, labels=6),
        row("2027-01-02", "2027-01-05", "v4", added=7, labels=8),
        row("2027-01-02", "2027-01-05", "v6", removed=9, labels=10),
    ]
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "series.csv")
        write_series(path, rows)
        series = churn_plot.load_series(path)

    assert [item.date_to for item in series.intervals] == [date(2027, 1, 2), date(2027, 1, 5)]
    assert series.intervals[1].interval_days == 3
    assert churn_plot.family_values(series, "v4", "added_pfx") == [2, 7]
    assert churn_plot.family_values(series, "v4", "removed_pfx", sign=-1) == [-1, 0]
    assert churn_plot.family_values(series, "v6", "removed_pfx", sign=-1) == [-5, -9]

    figure = churn_plot.build_figure(series)
    top_axis, bottom_axis = figure.axes
    assert list(labelled_line(top_axis, "IPv4 CIDRs added").get_ydata()) == [2, 7]
    assert list(labelled_line(top_axis, "IPv4 CIDRs removed").get_ydata()) == [-1, 0]
    assert list(labelled_line(top_axis, "IPv6 CIDRs added").get_ydata()) == [4, 0]
    assert list(labelled_line(top_axis, "IPv6 CIDRs removed").get_ydata()) == [-5, -9]
    assert list(labelled_line(bottom_axis, "IPv4 label-change runs").get_ydata()) == [3, 8]
    assert list(labelled_line(bottom_axis, "IPv6 label-change runs").get_ydata()) == [6, 10]
    assert len(top_axis.patches) == len(bottom_axis.patches) == 1
    churn_plot.plt.close(figure)


def test_one_family_series_is_supported():
    rows = [row("2028-02-01", "2028-02-02", "v4", added=1, labels=2)]
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "v4-only.csv")
        write_series(path, rows)
        series = churn_plot.load_series(path)

    figure = churn_plot.build_figure(series)
    top_axis, bottom_axis = figure.axes
    assert [
        line.get_label() for line in top_axis.lines
        if line.get_label().startswith("IPv")
    ] == ["IPv4 CIDRs added", "IPv4 CIDRs removed"]
    assert [line.get_label() for line in bottom_axis.lines] == ["IPv4 label-change runs"]
    churn_plot.plt.close(figure)


def test_figure_files_are_byte_stable():
    rows = [row("2028-02-01", "2028-02-02", "v4", added=1, labels=2)]
    with tempfile.TemporaryDirectory() as directory:
        csv_path = os.path.join(directory, "series.csv")
        write_series(csv_path, rows)
        series = churn_plot.load_series(csv_path)
        digests = []
        for suffix in ("one", "two"):
            figure = churn_plot.build_figure(series)
            pdf = os.path.join(directory, f"{suffix}.pdf")
            png = os.path.join(directory, f"{suffix}.png")
            churn_plot.save_figure(figure, pdf, png)
            churn_plot.plt.close(figure)
            digests.append(
                tuple(
                    hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    for path in (pdf, png)
                )
            )

    assert digests[0] == digests[1]


def main():
    test_arbitrary_series_with_gap_and_all_metrics()
    print("ok   arbitrary series with IPv4/IPv6, additions, removals, labels, and gap")
    test_one_family_series_is_supported()
    print("ok   one-family series")
    test_figure_files_are_byte_stable()
    print("ok   repeated rendering is byte-stable")


if __name__ == "__main__":
    main()
