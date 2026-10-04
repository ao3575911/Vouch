"""Tests for the trusted-process Unix-socket gateway."""

import socket
import threading
import time

import pytest

from capgate.audit import AuditLog
from capgate.contract import Contract
from capgate.isolation import IsolationError, UnixHarnessClient, UnixHarnessServer


@pytest.fixture
def isolated_harness(tmp_path):
    contract = Contract.from_dict(
        {
            "name": "socket-test",
            "version": "1",
            "agent_id": "agent",
            "max_steps": 2,
            "capabilities": [
                {
                    "tool": "read_note",
                    "effect": "allow",
                    "constraints": [{"name": "note", "equals": "public"}],
                }
            ],
        }
    )
    calls = []
    server = UnixHarnessServer(
        contract,
        AuditLog(tmp_path / "audit.jsonl"),
        tmp_path / "harness.sock",
        {"read_note": lambda note: calls.append(note) or {"note": note}},
    )
    stop_event = threading.Event()
    thread = threading.Thread(target=server.serve_forever, args=(stop_event,), daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    while not (tmp_path / "harness.sock").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert (tmp_path / "harness.sock").exists()
    yield server, UnixHarnessClient(tmp_path / "harness.sock"), calls
    stop_event.set()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_socket_gateway_keeps_permits_private_and_executes_allowed_tool(
    isolated_harness,
):
    server, client, calls = isolated_harness

    response = client.call("read_note", {"note": "public"})

    assert response == {"effect": "allow", "result": {"note": "public"}}
    assert calls == ["public"]
    assert "signature" not in response
    assert server.harness._signing_key not in response.values()


def test_socket_gateway_denies_unnamed_tool_without_execution(isolated_harness):
    _, client, calls = isolated_harness

    response = client.call("erase_registry", {})

    assert response["effect"] == "deny"
    assert "not named" in response["reason"]
    assert calls == []


def test_socket_gateway_does_not_accept_agent_identity_from_request(isolated_harness):
    server, _, calls = isolated_harness
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(server.socket_path))
    connection.sendall(b'{"agent_id":"agent","tool":"read_note","arguments":{"note":"public"}}')
    connection.shutdown(socket.SHUT_WR)
    response = connection.recv(4096)
    connection.close()

    assert b'"effect":"error"' in response
    assert calls == []


def test_socket_gateway_rejects_oversized_payload(isolated_harness):
    _, client, _ = isolated_harness

    with pytest.raises(IsolationError, match="too large"):
        client.call("read_note", {"note": "x" * 70_000})


def test_socket_gateway_rejects_non_socket_path(tmp_path):
    socket_path = tmp_path / "not-a-socket"
    socket_path.write_text("keep", encoding="utf-8")
    server = UnixHarnessServer(
        Contract.from_dict(
            {
                "name": "socket-test",
                "version": "1",
                "agent_id": "agent",
                "max_steps": 1,
            }
        ),
        AuditLog(tmp_path / "audit.jsonl"),
        socket_path,
        {},
    )

    with pytest.raises(IsolationError, match="non-socket"):
        server.serve_forever()

    assert socket_path.read_text(encoding="utf-8") == "keep"


def test_socket_gateway_rejects_malformed_message(isolated_harness):
    server, _, calls = isolated_harness
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(server.socket_path))
    connection.sendall(b'{"tool":"read_note","tool":"erase_registry"}')
    connection.shutdown(socket.SHUT_WR)
    response = connection.recv(4096)
    connection.close()

    assert b'"effect":"error"' in response
    assert calls == []
