"""Audit chain: every decision explained; any tamper detected offline."""

import json

import pytest
from conftest import AGENT

from capgate.audit import AuditChainError, AuditLog
from capgate.policy import Proposal

CALL = {"path": "/data/public/report.txt"}


def test_audit_explains_every_decision(harness, executor, audit_log):
    _, permit = harness.authorize(Proposal(AGENT, "read_file", CALL))
    executor.execute(permit, AGENT, "read_file", CALL)
    harness.authorize(Proposal(AGENT, "open_socket", {}))

    events = [r["event"] for r in audit_log.records()]
    assert events == ["decision.allow", "execution.completed", "decision.deny"]
    assert audit_log.verify() == 3

    deny = list(audit_log.records())[-1]
    assert "deny by default" in deny["detail"]["reason"]


def test_rejected_execution_is_audited(harness, executor, audit_log):
    _, permit = harness.authorize(Proposal(AGENT, "read_file", CALL))
    try:
        executor.execute(permit, AGENT, "read_file", {"path": "/etc/shadow"})
    except PermissionError:
        pass
    events = [r["event"] for r in audit_log.records()]
    assert "execution.rejected" in events


def test_tampered_record_detected(harness, audit_log):
    harness.authorize(Proposal(AGENT, "read_file", CALL))
    harness.authorize(Proposal(AGENT, "open_socket", {}))

    lines = audit_log.path.read_text().splitlines()
    record = json.loads(lines[0])
    record["detail"]["tool"] = "delete_file"
    lines[0] = json.dumps(record, sort_keys=True)
    audit_log.path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditChainError):
        audit_log.verify()


def test_deleted_record_detected(harness, audit_log):
    harness.authorize(Proposal(AGENT, "read_file", CALL))
    harness.authorize(Proposal(AGENT, "open_socket", {}))

    lines = audit_log.path.read_text().splitlines()
    audit_log.path.write_text(lines[1] + "\n")

    with pytest.raises(AuditChainError):
        audit_log.verify()


def test_empty_log_verifies(tmp_path):
    assert AuditLog(tmp_path / "empty.jsonl").verify() == 0
