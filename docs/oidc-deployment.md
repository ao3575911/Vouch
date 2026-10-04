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
- In-memory state is bounded. Expired codes, access tokens and replay nonces
  are swept on every request. Hard caps: 10,000 pending codes and 100,000
  replay nonces (new logins are refused with an error at the cap), 100,000
  access tokens (the oldest is evicted), 10,000 rate-limit buckets.
- Login proofs must carry an integer `issued_at` no more than 300 seconds old
  and no more than 30 seconds in the future. Each `(handle, nonce)` is
  accepted once.
- The server handles each connection on its own thread, up to 64 at once, and
  drops a connection that stalls for 10 seconds.
- Current rate limits are local to one process. They are not shared across
  workers or replicas and do not replace edge-level abuse controls.
- The bridge runs `Registry.verify()` at startup and refuses to start if the
  registry fails. Every login also checks the handle's manifest key against
  the event log. Use a dedicated registry mirror. Registry availability and
  freshness affect login; restart the bridge after pulling registry changes
  so the full check runs again. A relying party must independently validate
  the returned token and issuer.

## Behind a reverse proxy

The bridge binds to `127.0.0.1`, so a public deployment sits behind a reverse
proxy. By default the rate limiter keys on the socket peer, which is then the
proxy: every user shares one bucket. Tell the bridge which proxies to trust:

```bash
python -m vouch.oidc --registry ./registry --client myapp=https://app/cb \
    --trusted-proxy 127.0.0.1/32
```

`--trusted-proxy CIDR` is repeatable. `X-Forwarded-For` is only read when the
socket peer is inside a trusted range. The limiter then keys on the rightmost
address in `X-Forwarded-For` that is not itself a trusted proxy. Addresses to
its left were supplied by the client and are ignored, so a client can't pick
its own bucket. Without the flag the header is never read.

nginx example:

```nginx
server {
    listen 443 ssl;
    server_name vouch.example;
    # ssl_certificate ... ;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

`$proxy_add_x_forwarded_for` appends the client address nginx saw. If there
is a CDN or load balancer in front of nginx, add its ranges with more
`--trusted-proxy` flags, or set nginx's `real_ip` module up so it passes on
the right address.
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
