"""Shared validation helpers for the single-snapshot analyses."""

from __future__ import annotations

import ipaddress
import os
import re
import sys


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SNAPSHOT = os.path.join(
    BASE_DIR, "examples", "snapshots", "egress-2026-01-02.csv"
)
DEFAULT_BGP_TABLE = os.path.join(BASE_DIR, "data", "ipasn.dat")
DEFAULT_AS_NAMES = os.path.join(BASE_DIR, "data", "asnames.json")

_DATE_RE = re.compile(
    r"(?<!\d)(?P<year>20\d{2})[-_]?(?P<month>\d{2})[-_]?(?P<day>\d{2})(?!\d)"
)


class BgpLookupFailure(RuntimeError):
    """The offline IP-to-ASN lookup could not produce a usable result."""


class BgpContainmentFailure(RuntimeError):
    """The returned BGP prefix does not contain the full Apple prefix."""


def inferred_date(path):
    """Return an ISO date inferred from a dated filename, or None."""
    match = _DATE_RE.search(os.path.basename(os.fspath(path)))
    if not match:
        return None
    return (
        f"{match.group('year')}-{match.group('month')}-{match.group('day')}"
    )


def warn_date_mismatches(snapshot_path, artifacts):
    """Warn when dated BGP/ASN artifacts do not match the snapshot date."""
    snapshot_date = inferred_date(snapshot_path)
    if snapshot_date is None:
        return
    for label, artifact_path in artifacts:
        artifact_date = inferred_date(artifact_path)
        if artifact_date is not None and artifact_date != snapshot_date:
            print(
                f"WARNING: snapshot date {snapshot_date} differs from "
                f"{label} date {artifact_date}: {artifact_path}",
                file=sys.stderr,
            )


def lookup_covering_bgp(asndb, network):
    """Return ``(asn, prefix)`` after validating full-prefix containment.

    ``(None, None)`` is a normal unrouted result. Lookup/runtime failures and
    inconsistent or non-covering results are raised separately so callers can
    count and report them instead of silently treating them as unrouted.
    """
    try:
        result = asndb.lookup(str(network.network_address))
    except Exception as exc:
        raise BgpLookupFailure(
            f"lookup for {network.network_address} failed: {exc}"
        ) from exc

    if not isinstance(result, tuple) or len(result) != 2:
        raise BgpLookupFailure(f"unexpected lookup result for {network}: {result!r}")

    asn, prefix = result
    if asn is None and prefix is None:
        return None, None
    if asn is None or prefix is None:
        raise BgpLookupFailure(
            f"incomplete lookup result for {network}: ASN={asn!r}, prefix={prefix!r}"
        )

    try:
        covering = ipaddress.ip_network(prefix, strict=True)
    except ValueError as exc:
        raise BgpLookupFailure(
            f"invalid BGP prefix for {network}: {prefix!r}"
        ) from exc

    if covering.version != network.version or not network.subnet_of(covering):
        raise BgpContainmentFailure(
            f"Apple prefix {network} is not fully contained in returned "
            f"BGP prefix {covering} (AS{asn})"
        )

    return asn, str(covering)
