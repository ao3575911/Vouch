"""Exercise the sandbox boundary as an untrusted agent."""

import os
import socket

from capgate.isolation import UnixHarnessClient


def main() -> None:
    client = UnixHarnessClient(os.environ["CAPGATE_SOCKET"])

    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=1):
            raise AssertionError("agent unexpectedly reached the public network")
    except OSError:
        pass

    allowed = client.call(
        "read_note", {"note": "public"}
    )
    assert allowed == {"effect": "allow", "result": {"note": "public"}}, allowed
    assert "signature" not in allowed

    denied = client.call("erase_registry", {})
    assert denied["effect"] == "deny"

    print("PASS: allow-list enforced; permit stayed private; external network blocked")


if __name__ == "__main__":
    main()
