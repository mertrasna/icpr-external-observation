"""Immutable storage and naming profiles for protocol-diagnostic series."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class SeriesProfile:
    # Existing path and naming fields remain unchanged.
    name: str
    config_path: Path
    plan_path: Path
    client_root: Path
    derived_root: Path
    reports_root: Path
    runtime_root: Path
    reference_root: Path
    slot_prefix: str
    run_prefix: str
    analysis_family: str
    slot_conditions: tuple[str, ...]
    requires_origin_gate: bool
    denominator_id: str | None
    non_counted: bool


_PROFILES = {
    "dual_protocol": SeriesProfile(
        name="dual_protocol",
        config_path=ROOT / "examples" / "dual-protocol-config.json",
        plan_path=ROOT / "examples" / "dual-protocol-plan.json",
        client_root=ROOT / "client",
        derived_root=ROOT / "derived",
        reports_root=ROOT / "reports",
        runtime_root=ROOT / "runtime",
        reference_root=ROOT / "reference",
        slot_prefix="protocol",
        run_prefix="icprpd",
        analysis_family="dual_protocol",
        slot_conditions=("udp_permitted", "udp_blocked") * 5,
        requires_origin_gate=False,
        denominator_id=None,
        non_counted=False,
    ),
    "h3_required": SeriesProfile(
        name="h3_required",
        config_path=ROOT / "examples" / "h3-required-config.json",
        plan_path=ROOT / "examples" / "h3-required-plan.json",
        client_root=ROOT / "h3-required" / "client",
        derived_root=ROOT / "h3-required" / "derived",
        reports_root=ROOT / "h3-required" / "reports",
        runtime_root=ROOT / "h3-required" / "runtime",
        reference_root=ROOT / "h3-required" / "reference",
        slot_prefix="h3-required",
        run_prefix="icprh3",
        analysis_family="h3_required",
        slot_conditions=("udp_permitted", "udp_blocked") * 5,
        requires_origin_gate=True,
        denominator_id="h3-required-v1",
        non_counted=False,
    ),
}


def get_series_profile(name: str) -> SeriesProfile:
    try:
        return _PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown diagnostic series profile: {name}") from exc


def series_profile_names() -> tuple[str, ...]:
    return tuple(_PROFILES)


def get_profile_for_analysis_family(value: str) -> SeriesProfile:
    matches = [
        profile
        for profile in _PROFILES.values()
        if profile.analysis_family == value
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown diagnostic analysis family: {value}")
    return matches[0]
