"""Strict validation for non-counted H3-required control attestations."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping


class ControlError(RuntimeError):
    """Required non-counted control evidence is absent or contradictory."""


def _verified(value: Mapping[str, Any], label: str) -> None:
    if value.get("status") != "verified" or value.get("counted") is not False:
        raise ControlError(f"{label} is not a verified non-counted control")


def validate_controls_ready(
    controls: Mapping[str, Mapping[str, Any]], gate_session_id: str
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", gate_session_id):
        raise ControlError("control gate session identifier is invalid")
    missing = [name for name in ("warmup", "tcp_control", "pre_h3_control") if name not in controls]
    if missing:
        raise ControlError("required controls are absent: " + ", ".join(missing))
    warmup = controls["warmup"]
    tcp = controls["tcp_control"]
    h3 = controls["pre_h3_control"]
    _verified(warmup, "warm-up")
    _verified(tcp, "TCP suppression control")
    _verified(h3, "pre-series H3 control")
    if not (
        warmup.get("private_relay_state") == "off"
        and warmup.get("alt_svc_h3") is True
        and warmup.get("safari_healthz_opened") is True
        and warmup.get("safari_fully_quit_after") is True
    ):
        raise ControlError("warm-up does not establish H3 discovery and Safari cleanup")
    if tcp.get("gate_session_id") != gate_session_id:
        raise ControlError("TCP suppression control is bound to another gate session")
    try:
        ipaddress.IPv4Address(str(tcp.get("source_ipv4")))
    except ipaddress.AddressValueError as exc:
        raise ControlError("TCP suppression control lacks a valid source IPv4") from exc
    if not (
        tcp.get("tcp_connect_succeeded") is False
        and type(tcp.get("gate_counter_delta")) is int
        and int(tcp["gate_counter_delta"]) > 0
        and tcp.get("matching_server_tcp_syn") is True
    ):
        raise ControlError("TCP suppression control does not prove gate engagement")
    if h3.get("gate_session_id") != gate_session_id:
        raise ControlError("pre-series H3 control is bound to another gate session")
    if not (
        h3.get("private_relay_state") == "off"
        and h3.get("http_protocol") == "HTTP/3.0"
        and h3.get("remote_ip") == h3.get("expected_real_ip")
        and h3.get("fresh_server_quic_initial") is True
        and h3.get("exactly_one_caddy_record") is True
    ):
        raise ControlError("pre-series control does not prove direct destination HTTP/3")
    return {
        "status": "ready",
        "gate_session_id": gate_session_id,
        "counted": False,
        "validated_controls": ["warmup", "tcp_control", "pre_h3_control"],
    }
