"""Capgate: fail-closed capability-token MCP tool gate.

Research preview. The invariant: no tool invocation reaches an executor
without a valid, signed, single-use permit derived from a deterministic
policy decision against a named contract.
"""

from capgate.audit import AuditChainError, AuditLog
from capgate.contract import Contract, ContractError
from capgate.executor import Executor, PermitRejected
from capgate.harness import Harness
from capgate.permit import Permit, PermitError, canonical_call_hash
from capgate.policy import Decision, Proposal, evaluate

__all__ = [
    "AuditChainError",
    "AuditLog",
    "Contract",
    "ContractError",
    "Decision",
    "Executor",
    "Harness",
    "Permit",
    "PermitError",
    "PermitRejected",
    "Proposal",
    "canonical_call_hash",
    "evaluate",
]
