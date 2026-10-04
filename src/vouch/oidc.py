"""Minimal self-hostable OIDC provider backed by did:home proofs.

"Login with Vouch" for anything that speaks OpenID Connect (WordPress,
Nextcloud, forums, workplaces). The user proves control of their name by
signing a login statement with their root key; the bridge checks it
against the static registry — offline, nothing logged upstream — and
issues a standard EdDSA-signed ID token.

Run it:

    python -m vouch.oidc --registry ./registry --client myapp=https://app/cb

Endpoints: /.well-known/openid-configuration, /jwks.json, /authorize,
/token, /userinfo. Authorization code flow only; deny by default.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from capgate.didhome.proof import ProofError, verify_proof
from capgate.didhome.registry import Registry, RegistryError

PROOF_MAX_AGE_SECONDS = 300
CODE_TTL_SECONDS = 120
TOKEN_TTL_SECONDS = 3600
RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMITS = {"authorize": 20, "token": 30, "userinfo": 60}
MAX_RATE_LIMIT_BUCKETS = 10_000


class OIDCError(ValueError):
    """Raised on a rejected OIDC request."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_jwt(claims: dict[str, Any], key: Ed25519PrivateKey, kid: str) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    return signing_input + "." + _b64url(key.sign(signing_input.encode("ascii")))


def decode_jwt(token: str, key: Ed25519PublicKey) -> dict[str, Any]:
    try:
        head, body, sig = token.split(".")
        key.verify(_b64url_decode(sig), f"{head}.{body}".encode("ascii"))
        return json.loads(_b64url_decode(body))
    except (ValueError, InvalidSignature) as exc:
        raise OIDCError("invalid JWT") from exc


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    did: str
    handle: str
    nonce: str
    expires_at: float


@dataclass
class OIDCProvider:
    """The bridge: did:home proof in, standard OIDC tokens out."""

    registry: Registry
    issuer: str = "http://localhost:9000"
    clients: dict[str, str] = field(default_factory=dict)  # client_id -> redirect_uri
    signing_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    _codes: dict[str, _Code] = field(default_factory=dict)
    _access_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    _seen_proof_nonces: set[str] = field(default_factory=set)
    rate_limit_window_seconds: int = RATE_LIMIT_WINDOW_SECONDS
    rate_limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_RATE_LIMITS))
    _rate_events: OrderedDict[tuple[str, str], list[float]] = field(
        default_factory=OrderedDict
    )

    @property
    def kid(self) -> str:
        from capgate.didhome.manifest import public_key_hex

        return public_key_hex(self.signing_key.public_key())[:16]

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
        }

    def jwks(self) -> dict[str, Any]:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "keys": [{"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": _b64url(raw)}]
        }

    # -- authorization code flow -------------------------------------------

    def login_statement(self, client_id: str) -> str:
        """What the user must sign (with ``vouch card``) to log in."""
        return f"login:{client_id}"

    def _consume_rate_limit(self, endpoint: str, limiter_key: str, current: float) -> None:
        bucket_key = (endpoint, limiter_key or "global")
        window_start = current - self.rate_limit_window_seconds
        events = self._rate_events.pop(bucket_key, [])
        while events and events[0] <= window_start:
            events.pop(0)
        while self._rate_events:
            oldest_key = next(iter(self._rate_events))
            oldest_events = self._rate_events[oldest_key]
            if oldest_events and oldest_events[-1] > window_start:
                break
            self._rate_events.popitem(last=False)
        limit = self.rate_limits.get(endpoint, 0)
        if limit and len(events) >= limit:
            self._rate_events[bucket_key] = events
            raise OIDCError(f"rate limit exceeded for {endpoint}")
        if not limit:
            return
        events.append(current)
        self._rate_events[bucket_key] = events
        while len(self._rate_events) > MAX_RATE_LIMIT_BUCKETS:
            self._rate_events.popitem(last=False)

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        proof: dict[str, Any],
        nonce: str = "",
        now: float | None = None,
        limiter_key: str = "",
    ) -> str:
        """Validate a did:home login proof; return a one-time code."""
        current = time.time() if now is None else now
        self._consume_rate_limit("authorize", limiter_key or client_id, current)
        return self._authorize(client_id, redirect_uri, proof, nonce, current)

    def _authorize(
        self,
        client_id: str,
        redirect_uri: str,
        proof: dict[str, Any],
        nonce: str,
        current: float,
    ) -> str:
        if self.clients.get(client_id) != redirect_uri:
            raise OIDCError("unknown client_id or redirect_uri mismatch")
        handle = str(proof.get("handle", ""))
        try:
            manifest = self.registry.resolve(handle)
            verify_proof(proof, expected_public_key=manifest.root_public_key)
        except (RegistryError, ProofError, ValueError) as exc:
            raise OIDCError(f"login proof rejected: {exc}") from exc
        if proof.get("statement") != self.login_statement(client_id):
            raise OIDCError("proof statement does not authorize this client")
        if abs(current - float(proof["issued_at"])) > PROOF_MAX_AGE_SECONDS:
            raise OIDCError("login proof expired")
        if proof["nonce"] in self._seen_proof_nonces:
            raise OIDCError("login proof replayed")
        self._seen_proof_nonces.add(proof["nonce"])
        code = secrets.token_urlsafe(24)
        self._codes[code] = _Code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            did=manifest.did,
            handle=manifest.handle,
            nonce=nonce,
            expires_at=current + CODE_TTL_SECONDS,
        )
        return code

    def token(
        self,
        grant_type: str,
        code: str,
        client_id: str,
        redirect_uri: str,
        now: float | None = None,
        limiter_key: str = "",
    ) -> dict[str, Any]:
        """Exchange a one-time code for an EdDSA-signed ID token."""
        current = time.time() if now is None else now
        self._consume_rate_limit("token", limiter_key or client_id, current)
        return self._token(grant_type, code, client_id, redirect_uri, current)

    def _token(
        self,
        grant_type: str,
        code: str,
        client_id: str,
        redirect_uri: str,
        current: float,
    ) -> dict[str, Any]:
        if grant_type != "authorization_code":
            raise OIDCError("unsupported grant_type")
        grant = self._codes.pop(code, None)
        if grant is None or current > grant.expires_at:
            raise OIDCError("invalid or expired code")
        if grant.client_id != client_id or grant.redirect_uri != redirect_uri:
            raise OIDCError("code was issued to a different client")
        claims = {
            "iss": self.issuer,
            "sub": grant.did,
            "aud": client_id,
            "iat": int(current),
            "exp": int(current + TOKEN_TTL_SECONDS),
            "handle": grant.handle,
            "preferred_username": f"@{grant.handle}",
        }
        if grant.nonce:
            claims["nonce"] = grant.nonce
        access_token = secrets.token_urlsafe(24)
        self._access_tokens[access_token] = {
            "sub": grant.did,
            "handle": grant.handle,
            "expires_at": current + TOKEN_TTL_SECONDS,
        }
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "id_token": encode_jwt(claims, self.signing_key, self.kid),
        }

    def userinfo(
        self, authorization: str, now: float | None = None, limiter_key: str = ""
    ) -> dict[str, Any]:
        current = time.time() if now is None else now
        self._consume_rate_limit("userinfo", limiter_key or "bearer", current)
        if not authorization.startswith("Bearer "):
            raise OIDCError("missing bearer token")
        info = self._access_tokens.get(authorization.removeprefix("Bearer "))
        if info is None or current > info["expires_at"]:
            raise OIDCError("invalid or expired access token")
        return {
            "sub": info["sub"],
            "handle": info["handle"],
            "preferred_username": f"@{info['handle']}",
        }


def _make_handler(provider: OIDCProvider) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/.well-known/openid-configuration":
                self._send(200, provider.discovery())
            elif path == "/jwks.json":
                self._send(200, provider.jwks())
            elif path == "/userinfo":
                try:
                    self._send(
                        200,
                        provider.userinfo(
                            self.headers.get("Authorization", ""),
                            limiter_key=self.client_address[0],
                        ),
                    )
                except OIDCError as exc:
                    self._send(401, {"error": str(exc)})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            endpoint = {"/authorize": "authorize", "/token": "token"}.get(path)
            if endpoint is None:
                self._send(404, {"error": "not found"})
                return
            # Charge the per-IP limit before reading or parsing the body, so
            # malformed or oversized requests still count against it.
            current = time.time()
            try:
                provider._consume_rate_limit(endpoint, self.client_address[0], current)
            except OIDCError as exc:
                self._send(400, {"error": str(exc)})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8")
                if endpoint == "authorize":
                    body = json.loads(raw)
                    code = provider._authorize(
                        body["client_id"],
                        body["redirect_uri"],
                        body["proof"],
                        body.get("nonce", ""),
                        current,
                    )
                    self._send(
                        200,
                        {
                            "code": code,
                            "redirect": f"{body['redirect_uri']}?code={code}"
                            + (f"&state={body['state']}" if body.get("state") else ""),
                        },
                    )
                else:
                    form = {k: v[0] for k, v in parse_qs(raw).items()}
                    self._send(
                        200,
                        provider._token(
                            form.get("grant_type", ""),
                            form.get("code", ""),
                            form.get("client_id", ""),
                            form.get("redirect_uri", ""),
                            current,
                        ),
                    )
            except (OIDCError, KeyError, ValueError) as exc:
                self._send(400, {"error": str(exc)})

        def log_message(self, *args: Any) -> None:  # quiet by default
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vouch-oidc", description=__doc__)
    parser.add_argument("--registry", default="./registry")
    parser.add_argument("--issuer", default="http://localhost:9000")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--client",
        action="append",
        default=[],
        help="client_id=redirect_uri (repeatable)",
        required=True,
    )
    args = parser.parse_args(argv)
    clients = dict(item.split("=", 1) for item in args.client)
    provider = OIDCProvider(Registry(args.registry), issuer=args.issuer, clients=clients)
    server = HTTPServer(("127.0.0.1", args.port), _make_handler(provider))
    print(f"vouch OIDC bridge on {args.issuer} (clients: {', '.join(clients)})")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
