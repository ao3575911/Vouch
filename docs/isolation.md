# Isolated capgate demo

The in-process harness/executor remains the reference API. `capgate.isolation`
adds an IPC boundary for untrusted proposals: the agent sends bounded tool and
argument JSON over a Unix-domain socket, while the trusted service assigns the
contract's agent identity and owns the contract, signing key, audit log,
executor, and registered tools. The service evaluates each proposal and
executes only an explicitly permitted tool call. Signed permits and key
material are never returned to the agent.

Run the hostile-agent demo from the repository root:

```bash
docker compose -f examples/hostile-agent-demo/compose.yml build
docker compose -f examples/hostile-agent-demo/compose.yml up \
  --detach --wait harness
docker compose -f examples/hostile-agent-demo/compose.yml run \
  --rm --no-deps hostile-agent
docker compose -f examples/hostile-agent-demo/compose.yml down --volumes
```

The agent container has no network interface, runs read-only with all Linux
capabilities dropped, has no-new-privileges enabled, and receives the private
IPC volume read-only. The demo verifies that an allowed, constrained tool call
executes in the harness; an unknown tool is denied; a caller-supplied identity
field is rejected; and direct public-network access fails.

## Boundary and limitations

- The IPC request is one JSON object, limited to 64 KiB, with duplicate keys
  rejected. The server processes one connection at a time.
- The socket is mode `0666`; its protection depends on placing it in a
  dedicated directory/volume shared only with the untrusted agent. Do not put
  it in a generally accessible host directory.
- Each socket represents one contract identity. The caller cannot choose its
  audit identity. Use a distinct protected socket for each agent; this protocol
  does not authenticate multiple principals sharing one socket.
- This is process/container isolation, not a defense against a compromised
  host, Docker daemon, kernel, harness, or registered tool.
- The demo is not a general-purpose remote tool runner. Keep tool registration
  explicit and treat every registered tool as trusted code.
- CI exercises this Docker configuration. Deployment-specific hardening,
  independent security review, and recovery/operational procedures are still
  required before any production-readiness claim.
