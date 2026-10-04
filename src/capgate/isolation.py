"""Bounded Unix-socket boundary for untrusted agent proposals.

The trusted process owns the harness, signing key, executor, and tools. The
agent sends proposals only; permits never cross the socket.
"""

from __future__ import annotations

import json
import socket
import stat
import threading
from pathlib import Path
from typing import Any

from capgate.audit import AuditLog
from capgate.contract import Contract
from capgate.executor import Executor, PermitRejected, ToolFn
from capgate.harness import Harness
from capgate.policy import Proposal

MAX_MESSAGE_BYTES = 65_536
SOCKET_MODE = 0o666


class IsolationError(ValueError):
    """Raised when the local harness socket protocol fails."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IsolationError("duplicate JSON key")
        result[key] = value
    return result


def _read_message(connection: socket.socket) -> bytes:
    chunks = bytearray()
    while True:
        chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES + 1 - len(chunks)))
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
        if len(chunks) > MAX_MESSAGE_BYTES:
            raise IsolationError("request too large")


class UnixHarnessServer:
    """Authorize and execute proposals inside the trusted process."""

    def __init__(
        self,
        contract: Contract,
        audit_log: AuditLog,
        socket_path: str | Path,
        tools: dict[str, ToolFn],
    ):
        self.socket_path = Path(socket_path)
        self.contract = contract
        self.harness = Harness(contract, audit_log)
        self.executor = Executor(self.harness.verify_key, audit_log)
        for name, tool in tools.items():
            self.executor.register_tool(name, tool)

    def _handle(self, connection: socket.socket) -> None:
        try:
            raw = _read_message(connection)
            request = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
            if (
                not isinstance(request, dict)
                or set(request) != {"tool", "arguments"}
                or not isinstance(request["tool"], str)
                or not request["tool"]
                or not isinstance(request["arguments"], dict)
            ):
                raise IsolationError("invalid request")

            proposal = Proposal(self.contract.agent_id, request["tool"], request["arguments"])
            decision, permit = self.harness.authorize(proposal)
            if permit is None:
                response = {"effect": decision.effect, "reason": decision.reason}
            else:
                result = self.executor.execute(
                    permit, self.contract.agent_id, proposal.tool, proposal.arguments
                )
                response = {"effect": "allow", "result": result}
        except (IsolationError, json.JSONDecodeError, RecursionError):
            response = {"effect": "error", "reason": "invalid request"}
        except PermitRejected:
            response = {"effect": "deny", "reason": "permit rejected"}
        except Exception:  # noqa: BLE001 - isolate arbitrary registered tool failures
            response = {"effect": "error", "reason": "tool execution failed"}

        try:
            payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            payload = b'{"effect":"error","reason":"tool returned invalid data"}'
        if len(payload) > MAX_MESSAGE_BYTES:
            payload = b'{"effect":"error","reason":"response too large"}'
        try:
            connection.sendall(payload)
        except OSError:
            return

    def serve_forever(self, stop_event: threading.Event | None = None) -> None:
        """Listen until stopped; remove the socket file on exit."""
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            mode = self.socket_path.lstat().st_mode
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(mode):
                raise IsolationError("refusing to replace a non-socket path")
            self.socket_path.unlink()

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(SOCKET_MODE)
            listener.listen(16)
            listener.settimeout(0.2)
            while stop_event is None or not stop_event.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(2)
                    self._handle(connection)
        finally:
            listener.close()
            self.socket_path.unlink(missing_ok=True)


class UnixHarnessClient:
    """Submit a proposal without receiving its permit or signing material."""

    def __init__(self, socket_path: str | Path, timeout: float = 5):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        request = json.dumps(
            {"tool": tool, "arguments": arguments},
            separators=(",", ":"),
        ).encode("utf-8")
        if len(request) > MAX_MESSAGE_BYTES:
            raise IsolationError("request too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.socket_path)
                connection.sendall(request)
                connection.shutdown(socket.SHUT_WR)
                response = _read_message(connection)
            result = json.loads(response)
        except (OSError, json.JSONDecodeError, RecursionError) as exc:
            raise IsolationError("harness socket request failed") from exc
        if not isinstance(result, dict) or not isinstance(result.get("effect"), str):
            raise IsolationError("invalid harness response")
        return result
