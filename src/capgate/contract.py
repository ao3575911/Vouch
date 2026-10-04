"""Capability contract schema and validation.

A contract names an agent, the capabilities it may propose, the constraints
on each capability's arguments, approvers for escalation, and a hard step
budget. Anything not named in a contract is denied. Delegation is
non-transitive unless a capability explicitly escalates and names targets.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

VALID_EFFECTS = ("allow", "deny", "escalate")


class ContractError(ValueError):
    """Raised when a contract document fails schema validation."""


@dataclass(frozen=True)
class ArgConstraint:
    """Constraint on a single tool-call argument."""

    name: str
    equals: Any = None
    one_of: tuple[Any, ...] | None = None
    max_length: int | None = None

    def matches(self, value: Any) -> bool:
        if self.equals is not None and value != self.equals:
            return False
        if self.one_of is not None and value not in self.one_of:
            return False
        return self.max_length is None or (isinstance(value, str) and len(value) <= self.max_length)


@dataclass(frozen=True)
class Capability:
    """One tool the contract speaks about, with an explicit effect."""

    tool: str
    effect: str
    constraints: tuple[ArgConstraint, ...] = ()
    approvers: tuple[str, ...] = ()
    delegate_to: tuple[str, ...] = ()


@dataclass(frozen=True)
class Contract:
    """A named, versioned capability contract for one agent identity."""

    name: str
    version: str
    agent_id: str
    max_steps: int
    capabilities: tuple[Capability, ...] = ()
    approvers: tuple[str, ...] = ()

    def capability_for(self, tool: str) -> Capability | None:
        for cap in self.capabilities:
            if cap.tool == tool:
                return cap
        return None

    @staticmethod
    def from_dict(doc: dict[str, Any]) -> Contract:
        if not isinstance(doc, dict):
            raise ContractError("contract document must be a mapping")
        for key in ("name", "version", "agent_id", "max_steps"):
            if key not in doc:
                raise ContractError(f"contract missing required field: {key}")
        max_steps = doc["max_steps"]
        if not isinstance(max_steps, int) or max_steps < 1:
            raise ContractError("max_steps must be a positive integer")

        capabilities: list[Capability] = []
        for raw in doc.get("capabilities", []):
            if not isinstance(raw, dict) or "tool" not in raw or "effect" not in raw:
                raise ContractError("each capability needs 'tool' and 'effect'")
            effect = raw["effect"]
            if effect not in VALID_EFFECTS:
                raise ContractError(f"invalid effect {effect!r}; must be one of {VALID_EFFECTS}")
            if effect == "escalate" and not raw.get("approvers") and not doc.get("approvers"):
                raise ContractError(f"capability {raw['tool']!r} escalates but names no approvers")
            delegate_to = tuple(raw.get("delegate_to", ()))
            if delegate_to and effect != "escalate":
                raise ContractError(
                    f"capability {raw['tool']!r} delegates without an escalate effect; "
                    "delegation is non-transitive by default"
                )
            constraints = tuple(
                ArgConstraint(
                    name=c["name"],
                    equals=c.get("equals"),
                    one_of=tuple(c["one_of"]) if "one_of" in c else None,
                    max_length=c.get("max_length"),
                )
                for c in raw.get("constraints", [])
            )
            capabilities.append(
                Capability(
                    tool=raw["tool"],
                    effect=effect,
                    constraints=constraints,
                    approvers=tuple(raw.get("approvers", ())),
                    delegate_to=delegate_to,
                )
            )

        return Contract(
            name=doc["name"],
            version=str(doc["version"]),
            agent_id=doc["agent_id"],
            max_steps=max_steps,
            capabilities=tuple(capabilities),
            approvers=tuple(doc.get("approvers", ())),
        )

    @staticmethod
    def load(path: str | Path) -> Contract:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        return Contract.from_dict(doc)
