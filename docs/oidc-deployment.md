# OIDC bridge: deployment notes

The Vouch OIDC bridge is a research-preview reference implementation. It is
not yet validated against production identity-provider deployments or a
formal OIDC conformance suite. Existing tests exercise the local authorization
code flow; they do not establish interoperability with WordPress, Nextcloud,
or other relying parties.

## Operational constraints

- The built-in HTTP server binds to `127.0.0.1` and does not provide TLS.
  Keep it private and terminate TLS at a maintained reverse proxy if testing
  it remotely. Do not expose the development server directly to the Internet.
- Configure exact client redirect URIs. Do not use broad or user-controlled
  redirect patterns.
- The signing key, authorization codes, access tokens, replay state, and rate
  limit buckets are in memory. Restarting the process invalidates active
  tokens/codes and generates a new signing key unless an explicit persistent
  key-management design is added.
- Current rate limits are local to one process. They are bounded in memory but
  are not shared across workers or replicas and do not replace edge-level
  abuse controls.
- Use a dedicated registry mirror and verify it before operation. Registry
  availability and freshness affect login; a relying party must independently
  validate the returned token and issuer.
- Do not treat a proof as evidence of age, government identity, or any claim
  other than control of the signing key and the exact user-signed statement.

## Before production use

- Define persistent signing-key storage, rotation, backup, and incident
  response.
- Add and pass an OIDC conformance suite plus integration tests against
  representative relying parties.
- Review proxy configuration, issuer/JWKS handling, state/nonce checks, and
  operational monitoring with security owners.
- Select a shared, deployment-appropriate rate limiter if running multiple
  workers; retain network-edge limits as a separate control.
- Publish service-specific setup instructions only after those integrations
  have been exercised and their supported configuration documented.
