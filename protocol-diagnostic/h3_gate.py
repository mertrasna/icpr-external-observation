"""Pure policy rendering and validation for the H3-required origin TCP gate."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, fields
from typing import Any, Mapping


SESSION_PATTERN = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
RFC1918_NETWORKS = tuple(
    ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class GateError(RuntimeError):
    """The proposed or reported origin-gate state violates the frozen policy."""


@dataclass(frozen=True)
class GatePolicy:
    private_ipv4: str
    tcp_port: int = 443
    timeout_seconds: int = 1800
    minimum_remaining_seconds: int = 180
    chain_priority: int = -10
    chain_policy: str = "accept"
    set_name: str = "blocked_targets"
    counter_name: str = "tcp443_dropped"


@dataclass(frozen=True)
class GateStatus:
    session_id: str
    table_name: str
    table_count: int
    chain_count: int
    set_count: int
    counter_count: int
    rule_count: int
    chain_priority: int
    chain_policy: str
    target_present: bool
    target_ipv4: str
    remaining_seconds: int
    packets: int
    bytes: int
    timer_active: bool
    timer_unit: str
    caddy_active: bool
    capture_active: bool
    exact_rule: str


def canonical_rfc1918_ipv4(value: Any) -> str:
    try:
        address = ipaddress.IPv4Address(str(value))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise GateError(f"invalid origin private IPv4: {value!r}") from exc
    if not any(address in network for network in RFC1918_NETWORKS):
        raise GateError("origin private IPv4 must be within an RFC 1918 network")
    return str(address)


def _validate_session_id(session_id: str) -> None:
    if not SESSION_PATTERN.fullmatch(session_id):
        raise GateError(f"invalid H3 gate session identifier: {session_id!r}")


def table_name_for_session(session_id: str) -> str:
    _validate_session_id(session_id)
    return "icpr_h3req_" + session_id.replace("-", "_")


def timer_unit_for_session(session_id: str) -> str:
    _validate_session_id(session_id)
    return f"icpr-h3req-rollback-{session_id}.timer"


def exact_rule(policy: GatePolicy) -> str:
    return (
        f"ip daddr @{policy.set_name} tcp dport {policy.tcp_port} "
        f"counter name {policy.counter_name} drop"
    )


def render_nft_batch(policy: GatePolicy, session_id: str) -> str:
    private_ipv4 = canonical_rfc1918_ipv4(policy.private_ipv4)
    if policy.tcp_port != 443:
        raise GateError("H3-required origin gate may target only TCP port 443")
    if policy.timeout_seconds != 1800:
        raise GateError("H3-required origin gate timeout must remain 1800 seconds")
    if policy.chain_priority != -10 or policy.chain_policy != "accept":
        raise GateError("H3-required input chain must remain priority -10 policy accept")
    table_name = table_name_for_session(session_id)
    return "\n".join(
        (
            f"add table ip {table_name}",
            (
                f"add chain ip {table_name} input "
                f"{{ type filter hook input priority {policy.chain_priority}; "
                f"policy {policy.chain_policy}; }}"
            ),
            (
                f"add set ip {table_name} {policy.set_name} "
                f"{{ type ipv4_addr; flags timeout; timeout {policy.timeout_seconds}s; }}"
            ),
            f"add counter ip {table_name} {policy.counter_name}",
            (
                f"add rule ip {table_name} input {exact_rule(policy)} "
                f'comment "icpr-h3-required {session_id}"'
            ),
            (
                f"add element ip {table_name} {policy.set_name} "
                f"{{ {private_ipv4} timeout {policy.timeout_seconds}s }}"
            ),
            "",
        )
    )


def parse_gate_status(value: str | Mapping[str, Any]) -> GateStatus:
    if isinstance(value, str):
        try:
            loaded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise GateError(f"origin-gate status is not valid JSON: {exc}") from exc
    else:
        loaded = dict(value)
    if not isinstance(loaded, dict):
        raise GateError("origin-gate status must be a JSON object")
    required = {field.name for field in fields(GateStatus)}
    missing = sorted(required - set(loaded))
    if missing:
        raise GateError("origin-gate status lacks fields: " + ", ".join(missing))
    boolean_fields = {
        "target_present",
        "timer_active",
        "caddy_active",
        "capture_active",
    }
    integer_fields = {
        "table_count",
        "chain_count",
        "set_count",
        "counter_count",
        "rule_count",
        "chain_priority",
        "remaining_seconds",
        "packets",
        "bytes",
    }
    for name in boolean_fields:
        if type(loaded[name]) is not bool:
            raise GateError(f"origin-gate status field {name} must be boolean")
    for name in integer_fields:
        if type(loaded[name]) is not int:
            raise GateError(f"origin-gate status field {name} must be an integer")
    for name in required - boolean_fields - integer_fields:
        if not isinstance(loaded[name], str):
            raise GateError(f"origin-gate status field {name} must be a string")
    return GateStatus(**{name: loaded[name] for name in required})


def validate_gate_status(
    status: GateStatus,
    policy: GatePolicy,
    minimum_remaining_seconds: int | None = None,
) -> GateStatus:
    _validate_session_id(status.session_id)
    expected_table = table_name_for_session(status.session_id)
    if status.table_name != expected_table:
        raise GateError("origin-gate table is not bound to the reported session")
    if (
        status.table_count,
        status.chain_count,
        status.set_count,
        status.counter_count,
        status.rule_count,
    ) != (1, 1, 1, 1, 1):
        raise GateError("origin-gate status does not describe one exact table/chain/set/counter/rule")
    if (
        status.chain_priority != policy.chain_priority
        or status.chain_policy != policy.chain_policy
    ):
        raise GateError("origin-gate input chain differs from priority -10 policy accept")
    if not status.target_present or status.target_ipv4 != policy.private_ipv4:
        raise GateError("origin-gate target is absent or differs from the private origin")
    threshold = max(
        policy.minimum_remaining_seconds,
        minimum_remaining_seconds or policy.minimum_remaining_seconds,
    )
    if status.remaining_seconds < threshold:
        raise GateError(
            f"origin-gate has {status.remaining_seconds}s remaining; {threshold}s required"
        )
    if status.remaining_seconds > policy.timeout_seconds:
        raise GateError("origin-gate remaining lifetime exceeds the frozen timeout")
    if status.packets < 0 or status.bytes < 0:
        raise GateError("origin-gate counters cannot be negative")
    if not status.timer_active:
        raise GateError("independent origin-gate rollback timer is not active")
    if status.timer_unit != timer_unit_for_session(status.session_id):
        raise GateError("origin-gate rollback timer is bound to another session")
    if not status.caddy_active or not status.capture_active:
        raise GateError("Caddy and continuous capture must remain active")
    if " ".join(status.exact_rule.split()) != exact_rule(policy):
        raise GateError("origin-gate rule is broader than or different from the frozen rule")
    return status
