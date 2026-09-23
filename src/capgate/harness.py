"""The harness: authorize proposals, sign permits, write audit records.

The harness owns the signing key and the contract. The agent process never
sees either. A proposal either yields a signed permit or a recorded denial.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from capgate.audit import AuditLog
from capgate.contract import Contract
from capgate.permit import DEFAULT_TTL_SECONDS, Permit, issue_permit
from capgate.policy import Decision, Proposal, evaluate


class Harness:
    """Deterministic authorizer. Proposal in; (decision, permit-or-None) out."""

    def __init__(
        self,
        contract: Contract,
        audit_log: AuditLog,
        signing_key: Ed25519PrivateKey | None = None,
        permit_ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ):
        self._contract = contract
        self._audit = audit_log
        self._signing_key = signing_key or Ed25519PrivateKey.generate()
        self._permit_ttl = permit_ttl_seconds
        self._steps_used = 0

    @property
    def verify_key(self) -> Ed25519PublicKey:
        """Public key for executors. The private key never leaves the harness."""
        return self._signing_key.public_key()

    def authorize(self, proposal: Proposal) -> tuple[Decision, Permit | None]:
        decision = evaluate(self._contract, proposal, self._steps_used)
        permit: Permit | None = None
        if decision.effect == "allow":
            self._steps_used += 1
            permit = issue_permit(
                signing_key=self._signing_key,
                agent_id=proposal.agent_id,
                tool=proposal.tool,
                arguments=proposal.arguments,
                contract_name=decision.contract_name,
                contract_version=decision.contract_version,
                ttl_seconds=self._permit_ttl,
            )
        self._audit.append(
            event=f"decision.{decision.effect}",
            agent_id=proposal.agent_id,
            detail={
                "tool": proposal.tool,
                "arguments": proposal.arguments,
                "reason": decision.reason,
                "contract": f"{decision.contract_name}@{decision.contract_version}",
                "clause": decision.clause,
                "approvers": list(decision.approvers),
                "permit_id": permit.permit_id if permit else None,
            },
        )
        return decision, permit
