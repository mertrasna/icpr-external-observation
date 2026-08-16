"""Bounded SSH client for the H3-required server origin gate."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from h3_gate import (
    GateError,
    GatePolicy,
    canonical_rfc1918_ipv4,
    parse_gate_status,
    validate_gate_status,
)


SESSION_PATTERN = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
SSH = "/usr/bin/ssh"
HELPER_PATH = "/usr/local/sbin/icpr-h3-origin-gate"


class ServerGateError(RuntimeError):
    """Remote gate invocation or returned evidence is invalid."""


class ServerGateClient:
    def __init__(
        self,
        host: str,
        key_path: Path,
        helper_path: str = HELPER_PATH,
        *,
        policy: GatePolicy,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*@[A-Za-z0-9.-]+", host):
            raise ServerGateError("SSH target is invalid")
        if helper_path != HELPER_PATH:
            raise ServerGateError("server gate helper path differs from the frozen path")
        resolved_key = key_path.expanduser().resolve()
        if any(character in str(resolved_key) for character in ("\n", "\r", "\x00")):
            raise ServerGateError("SSH key path is invalid")
        try:
            private_ipv4 = canonical_rfc1918_ipv4(policy.private_ipv4)
        except GateError as exc:
            raise ServerGateError(str(exc)) from exc
        if private_ipv4 != policy.private_ipv4:
            raise ServerGateError("origin-gate private IPv4 must be canonical")
        self.host = host
        self.key_path = resolved_key
        self.helper_path = helper_path
        self.runner = runner
        self.policy = policy

    def _invoke(self, action: str, session_id: str) -> dict[str, Any]:
        if action not in {"validate", "arm", "status", "disarm"}:
            raise ServerGateError("unsupported server gate action")
        if not SESSION_PATTERN.fullmatch(session_id):
            raise ServerGateError("invalid server gate session identifier")
        argv = [
            SSH,
            "-i",
            str(self.key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            self.host,
            "sudo",
            "--non-interactive",
            self.helper_path,
            action,
            session_id,
            self.policy.private_ipv4,
        ]
        completed = self.runner(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ServerGateError(
                f"remote gate {action} failed with status {completed.returncode}"
            )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ServerGateError(f"remote gate output is not one JSON object: {exc}") from exc
        if not isinstance(value, dict):
            raise ServerGateError("remote gate output is not a JSON object")
        if value.get("session_id", session_id) != session_id:
            raise ServerGateError("remote gate output is bound to another session")
        return value

    def validate(self, session_id: str) -> dict[str, Any]:
        value = self._invoke("validate", session_id)
        if value.get("status") != "validated" or value.get("mutated") is not False:
            raise ServerGateError("remote gate validation did not prove non-mutation")
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("nft_batch_sha256", ""))):
            raise ServerGateError("remote gate validation lacks the rendered batch hash")
        return value

    def _validated_status(self, action: str, session_id: str) -> dict[str, Any]:
        value = self._invoke(action, session_id)
        try:
            status = parse_gate_status(value)
            validate_gate_status(status, self.policy, self.policy.minimum_remaining_seconds)
        except GateError as exc:
            raise ServerGateError(str(exc)) from exc
        return asdict(status)

    def arm(self, session_id: str) -> dict[str, Any]:
        return self._validated_status("arm", session_id)

    def snapshot(self, session_id: str) -> dict[str, Any]:
        return self._validated_status("status", session_id)

    def disarm(self, session_id: str) -> dict[str, Any]:
        value = self._invoke("disarm", session_id)
        if (
            value.get("status") != "disarmed"
            or value.get("table_absent") is not True
            or value.get("target_removed") is not True
        ):
            raise ServerGateError("remote gate disarm did not prove exact restoration")
        return value
