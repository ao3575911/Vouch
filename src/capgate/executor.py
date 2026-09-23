"""The executor: the only component that touches tools.

Before forwarding a call it validates the permit signature, expiry,
single-use nonce, agent identity, and the exact call hash. Any mismatch is
a structural denial — the tool is never invoked.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from capgate.audit import AuditLog
from capgate.permit import Permit, PermitError, canonical_call_hash, verify_permit

ToolFn = Callable[..., Any]


class PermitRejected(PermissionError):
    """Raised when a permit fails validation. The tool was not invoked."""


class Executor:
    """Validates permits and executes tool calls. Holds tool credentials."""

    def __init__(self, verify_key: Ed25519PublicKey, audit_log: AuditLog):
        self._verify_key = verify_key
        self._audit = audit_log
        self._tools: dict[str, ToolFn] = {}
        self._used_permit_ids: set[str] = set()

    def register_tool(self, name: str, fn: ToolFn) -> None:
        self._tools[name] = fn

    def execute(
        self,
        permit: Permit,
        agent_id: str,
        tool: str,
        arguments: dict[str, Any],
        now: float | None = None,
    ) -> Any:
        def reject(reason: str) -> PermitRejected:
            self._audit.append(
                event="execution.rejected",
                agent_id=agent_id,
                detail={
                    "tool": tool,
                    "permit_id": permit.permit_id,
                    "reason": reason,
                },
            )
            return PermitRejected(reason)

        try:
            verify_permit(self._verify_key, permit, now=now)
        except PermitError as exc:
            raise reject(str(exc)) from exc

        if permit.permit_id in self._used_permit_ids:
            raise reject("permit already used; single-use only")
        if permit.agent_id != agent_id:
            raise reject("permit was issued to a different agent")
        if permit.call_hash != canonical_call_hash(tool, arguments):
            raise reject("call does not match the authorized call hash")
        if tool not in self._tools:
            raise reject(f"tool {tool!r} is not registered with this executor")

        self._used_permit_ids.add(permit.permit_id)
        result = self._tools[tool](**arguments)
        self._audit.append(
            event="execution.completed",
            agent_id=agent_id,
            detail={
                "tool": tool,
                "permit_id": permit.permit_id,
                "contract": f"{permit.contract_name}@{permit.contract_version}",
            },
        )
        return result
