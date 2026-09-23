"""Hash-chained, append-only audit log.

Each record embeds the SHA-256 of the previous record, so any tampering,
reordering, or deletion breaks the chain. Verification is offline: it needs
only the log itself.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


class AuditChainError(ValueError):
    """Raised when the audit chain fails verification."""


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_hash(record: dict[str, Any]) -> str:
    unhashed = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(_canonical_json(unhashed)).hexdigest()


class AuditLog:
    """Append-only JSONL audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        last = GENESIS_HASH
        for record in self.records():
            last = record["record_hash"]
        return last

    def append(
        self,
        event: str,
        agent_id: str,
        detail: dict[str, Any],
        now: float | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "timestamp": time.time() if now is None else now,
            "event": event,
            "agent_id": agent_id,
            "detail": detail,
            "prev_hash": self._last_hash(),
        }
        record["record_hash"] = _record_hash(record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> int:
        """Verify the full chain. Returns record count; raises on tampering."""
        prev = GENESIS_HASH
        count = 0
        for i, record in enumerate(self.records()):
            if record.get("prev_hash") != prev:
                raise AuditChainError(f"chain broken at record {i}: prev_hash mismatch")
            if record.get("record_hash") != _record_hash(record):
                raise AuditChainError(f"record {i} content does not match its hash")
            prev = record["record_hash"]
            count += 1
        return count
