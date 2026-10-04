"""Run the trusted harness and executor for the isolated hostile-agent demo."""

import os
from pathlib import Path

from capgate.audit import AuditLog
from capgate.contract import Contract
from capgate.isolation import UnixHarnessServer


def read_note(note: str) -> dict[str, str]:
    return {"note": note}


def main() -> None:
    root = Path(__file__).parent
    contract = Contract.load(root / "contract.yaml")
    server = UnixHarnessServer(
        contract,
        AuditLog(os.environ["CAPGATE_AUDIT"]),
        os.environ["CAPGATE_SOCKET"],
        {"read_note": read_note},
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
