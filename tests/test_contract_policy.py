"""Contract schema and deterministic policy evaluation tests."""

import pytest
from conftest import AGENT, CONTRACT_DOC

from capgate.contract import Contract, ContractError
from capgate.policy import Proposal, evaluate


def test_contract_requires_core_fields():
    with pytest.raises(ContractError):
        Contract.from_dict({"name": "x", "version": "1"})


def test_contract_rejects_invalid_effect():
    doc = dict(CONTRACT_DOC, capabilities=[{"tool": "x", "effect": "maybe"}])
    with pytest.raises(ContractError):
        Contract.from_dict(doc)


def test_contract_escalate_requires_approvers():
    doc = dict(CONTRACT_DOC, approvers=[], capabilities=[{"tool": "x", "effect": "escalate"}])
    with pytest.raises(ContractError):
        Contract.from_dict(doc)


def test_contract_delegation_requires_escalation():
    doc = dict(
        CONTRACT_DOC,
        capabilities=[{"tool": "x", "effect": "allow", "delegate_to": ["agent://other"]}],
    )
    with pytest.raises(ContractError):
        Contract.from_dict(doc)


def test_allow_within_constraints(contract):
    decision = evaluate(
        contract, Proposal(AGENT, "read_file", {"path": "/data/public/report.txt"}), 0
    )
    assert decision.effect == "allow"
    assert decision.clause == "capability:read_file"


def test_unnamed_tool_denied_by_default(contract):
    decision = evaluate(contract, Proposal(AGENT, "open_socket", {}), 0)
    assert decision.effect == "deny"
    assert "deny by default" in decision.reason


def test_explicit_deny(contract):
    decision = evaluate(contract, Proposal(AGENT, "delete_file", {"path": "/x"}), 0)
    assert decision.effect == "deny"


def test_constraint_violation_denied(contract):
    decision = evaluate(contract, Proposal(AGENT, "read_file", {"path": "/etc/shadow"}), 0)
    assert decision.effect == "deny"


def test_missing_constrained_argument_denied(contract):
    decision = evaluate(contract, Proposal(AGENT, "read_file", {}), 0)
    assert decision.effect == "deny"


def test_wrong_agent_denied(contract):
    decision = evaluate(
        contract, Proposal("agent://impostor", "read_file", {"path": "/data/public/report.txt"}), 0
    )
    assert decision.effect == "deny"


def test_step_budget_exhaustion_denied(contract):
    decision = evaluate(
        contract,
        Proposal(AGENT, "read_file", {"path": "/data/public/report.txt"}),
        contract.max_steps,
    )
    assert decision.effect == "deny"
    assert decision.clause == "max_steps"


def test_escalation_names_approvers(contract):
    decision = evaluate(contract, Proposal(AGENT, "send_email", {"to": "a@b.c"}), 0)
    assert decision.effect == "escalate"
    assert decision.approvers == ("security@example.com",)


def test_example_contract_loads():
    contract = Contract.load("contracts/example.yaml")
    assert contract.name == "research-assistant"
    assert contract.capability_for("delete_file").effect == "deny"
