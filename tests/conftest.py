"""Shared fixtures: a gate wired end-to-end against an in-memory tool."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.audit import AuditLog
from capgate.contract import Contract
from capgate.executor import Executor
from capgate.harness import Harness

AGENT = "agent://research-assistant"

CONTRACT_DOC = {
    "name": "research-assistant",
    "version": "1",
    "agent_id": AGENT,
    "max_steps": 5,
    "approvers": ["security@example.com"],
    "capabilities": [
        {
            "tool": "read_file",
            "effect": "allow",
            "constraints": [
                {"name": "path", "one_of": ["/data/public/report.txt"]},
            ],
        },
        {"tool": "send_email", "effect": "escalate"},
        {"tool": "delete_file", "effect": "deny"},
    ],
}


@pytest.fixture
def contract() -> Contract:
    return Contract.from_dict(CONTRACT_DOC)


@pytest.fixture
def audit_log(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def harness(contract, audit_log, signing_key) -> Harness:
    return Harness(contract, audit_log, signing_key=signing_key)


@pytest.fixture
def executor(harness, audit_log) -> Executor:
    ex = Executor(harness.verify_key, audit_log)
    ex.register_tool("read_file", lambda path: f"contents of {path}")
    return ex
