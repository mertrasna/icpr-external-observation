#!/usr/bin/env python3
"""Verify researcher-supplied data manifests without modifying their files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    """A manifest is malformed or names an unsafe path."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_manifest_path(base: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise VerificationError(f"unsafe manifest path: {value!r}")
    return base / relative


def display_path(path: Path) -> str:
    """Return a stable readable path for data inside or outside the repository."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def verify_snapshot_manifest(path: Path) -> tuple[int, list[str]]:
    if not path.is_file():
        raise VerificationError(f"snapshot manifest not found: {path}")

    failures: list[str] = []
    checked = 0
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"path", "bytes", "sha256"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise VerificationError(
                f"{path} must contain columns: {', '.join(sorted(required))}"
            )
        for row_number, row in enumerate(reader, start=2):
            expected_hash = row["sha256"].strip().lower()
            if not SHA256_RE.fullmatch(expected_hash):
                raise VerificationError(f"invalid SHA-256 at {path}:{row_number}")
            try:
                expected_size = int(row["bytes"])
            except ValueError as exc:
                raise VerificationError(
                    f"invalid byte count at {path}:{row_number}"
                ) from exc
            candidate = resolve_manifest_path(path.parent, row["path"].strip())
            checked += 1
            if not candidate.is_file():
                failures.append(f"missing: {display_path(candidate)}")
                continue
            if candidate.stat().st_size != expected_size:
                failures.append(f"size mismatch: {display_path(candidate)}")
                continue
            if sha256_file(candidate) != expected_hash:
                failures.append(f"hash mismatch: {display_path(candidate)}")
    return checked, failures


def verify_sha256_manifest(path: Path) -> tuple[int, list[str]]:
    if not path.is_file():
        raise VerificationError(f"routing manifest not found: {path}")

    failures: list[str] = []
    checked = 0
    with path.open(encoding="utf-8") as handle:
        for row_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0].lower()):
                raise VerificationError(f"invalid manifest row at {path}:{row_number}")
            filename = parts[1].lstrip("*")
            candidate = resolve_manifest_path(path.parent, filename)
            checked += 1
            if not candidate.is_file():
                failures.append(f"missing: {display_path(candidate)}")
                continue
            if sha256_file(candidate) != parts[0].lower():
                failures.append(f"hash mismatch: {display_path(candidate)}")
    return checked, failures


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--snapshot-manifest",
        type=Path,
        help="CSV manifest with path, bytes, and sha256 columns",
    )
    argument_parser.add_argument(
        "--routing-manifest",
        type=Path,
        help="SHA-256 manifest for routing inputs",
    )
    return argument_parser


def main() -> int:
    argument_parser = parser()
    args = argument_parser.parse_args()
    if args.snapshot_manifest is None and args.routing_manifest is None:
        argument_parser.error(
            "provide --snapshot-manifest, --routing-manifest, or both"
        )

    checked = 0
    failures: list[str] = []
    try:
        if args.snapshot_manifest is not None:
            snapshot_count, snapshot_failures = verify_snapshot_manifest(
                args.snapshot_manifest.resolve()
            )
            checked += snapshot_count
            failures.extend(snapshot_failures)
        if args.routing_manifest is not None:
            routing_count, routing_failures = verify_sha256_manifest(
                args.routing_manifest.resolve()
            )
            checked += routing_count
            failures.extend(routing_failures)
    except VerificationError as exc:
        print(f"data verification error: {exc}", file=sys.stderr)
        return 2

    if failures:
        print(f"data verification failed: {len(failures)} of {checked} files")
        for failure in failures:
            print(f"- {failure}")
        print("See docs/data-availability.md for input and manifest guidance.")
        return 1

    print(f"data verified: {checked} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
