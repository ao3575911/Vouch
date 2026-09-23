"""Deterministic policy evaluation. No model in the decision path.

A proposal is evaluated against exactly one named contract. The outcome is
allow, deny, or escalate — deny by default for anything the contract does
not explicitly name or that violates a constraint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Proposal:
    """A tool invocation the agent wants to make. The agent only proposes."""

    agent_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """The deterministic outcome of evaluating a proposal against a contract."""

    effect: str  # "allow" | "deny" | "escalate"
    reason: str
    contract_name: str
    contract_version: str
    clause: str | None = None
    approvers: tuple[str, ...] = ()


def evaluate(contract, proposal: Proposal, steps_used: int) -> Decision:
    """Evaluate a proposal. Deny-by-default: only an explicit allow allows."""

    def deny(reason: str, clause: str | None = None) -> Decision:
        return Decision(
            effect="deny",
            reason=reason,
            contract_name=contract.name,
            contract_version=contract.version,
            clause=clause,
        )

    if proposal.agent_id != contract.agent_id:
        return deny(f"agent {proposal.agent_id!r} is not named by contract {contract.name!r}")

    if steps_used >= contract.max_steps:
        return deny(f"step budget exhausted ({steps_used}/{contract.max_steps})", "max_steps")

    cap = contract.capability_for(proposal.tool)
    if cap is None:
        return deny(f"tool {proposal.tool!r} not named in contract; deny by default")

    clause = f"capability:{cap.tool}"

    if cap.effect == "deny":
        return deny(f"tool {proposal.tool!r} explicitly denied", clause)

    for constraint in cap.constraints:
        if constraint.name not in proposal.arguments:
            return deny(
                f"argument {constraint.name!r} required by contract but missing", clause
            )
        if not constraint.matches(proposal.arguments[constraint.name]):
            return deny(
                f"argument {constraint.name!r} violates contract constraint", clause
            )

    if cap.effect == "escalate":
        approvers = cap.approvers or contract.approvers
        return Decision(
            effect="escalate",
            reason=f"tool {proposal.tool!r} requires approval",
            contract_name=contract.name,
            contract_version=contract.version,
            clause=clause,
            approvers=approvers,
        )

    return Decision(
        effect="allow",
        reason=f"tool {proposal.tool!r} allowed within constraints",
        contract_name=contract.name,
        contract_version=contract.version,
        clause=clause,
    )
