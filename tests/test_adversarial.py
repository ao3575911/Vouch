"""Adversarial tests: the paths an attacker would take, all denied."""

import pytest
from conftest import AGENT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.executor import PermitRejected
from capgate.permit import PermitError, issue_permit, verify_permit
from capgate.policy import Proposal

CALL = {"path": "/data/public/report.txt"}


def authorize(harness):
    decision, permit = harness.authorize(Proposal(AGENT, "read_file", CALL))
    assert decision.effect == "allow" and permit is not None
    return permit


def test_happy_path_authorize_then_execute(harness, executor):
    permit = authorize(harness)
    result = executor.execute(permit, AGENT, "read_file", CALL)
    assert result == "contents of /data/public/report.txt"


def test_unauthorized_tool_never_gets_a_permit(harness):
    decision, permit = harness.authorize(Proposal(AGENT, "open_socket", {}))
    assert decision.effect == "deny"
    assert permit is None


def test_permit_replay_denied(harness, executor):
    permit = authorize(harness)
    executor.execute(permit, AGENT, "read_file", CALL)
    with pytest.raises(PermitRejected, match="single-use"):
        executor.execute(permit, AGENT, "read_file", CALL)


def test_expired_permit_denied(harness, executor):
    permit = authorize(harness)
    with pytest.raises(PermitRejected, match="expired"):
        executor.execute(permit, AGENT, "read_file", CALL, now=permit.expires_at + 1)


def test_argument_tampering_after_authorization_denied(harness, executor):
    permit = authorize(harness)
    with pytest.raises(PermitRejected, match="call hash"):
        executor.execute(permit, AGENT, "read_file", {"path": "/etc/shadow"})


def test_tool_swap_after_authorization_denied(harness, executor):
    permit = authorize(harness)
    executor.register_tool("delete_file", lambda path: "deleted")
    with pytest.raises(PermitRejected, match="call hash"):
        executor.execute(permit, AGENT, "delete_file", CALL)


def test_permit_forged_by_agent_key_denied(harness, executor):
    attacker_key = Ed25519PrivateKey.generate()
    forged = issue_permit(
        signing_key=attacker_key,
        agent_id=AGENT,
        tool="read_file",
        arguments=CALL,
        contract_name="research-assistant",
        contract_version="1",
    )
    with pytest.raises(PermitRejected, match="signature"):
        executor.execute(forged, AGENT, "read_file", CALL)


def test_permit_field_tampering_breaks_signature(harness):
    import dataclasses

    permit = authorize(harness)
    tampered = dataclasses.replace(permit, agent_id="agent://impostor")
    with pytest.raises(PermitError, match="signature"):
        verify_permit(harness.verify_key, tampered)


def test_stolen_permit_wrong_agent_denied(harness, executor):
    permit = authorize(harness)
    with pytest.raises(PermitRejected, match="different agent"):
        executor.execute(permit, "agent://impostor", "read_file", CALL)


def test_delegation_without_escalation_denied(harness):
    decision, permit = harness.authorize(Proposal("agent://delegate", "read_file", CALL))
    assert decision.effect == "deny"
    assert permit is None


def test_step_budget_stops_permit_issuance(harness, contract):
    for _ in range(contract.max_steps):
        decision, _ = harness.authorize(Proposal(AGENT, "read_file", CALL))
        assert decision.effect == "allow"
    decision, permit = harness.authorize(Proposal(AGENT, "read_file", CALL))
    assert decision.effect == "deny"
    assert permit is None
