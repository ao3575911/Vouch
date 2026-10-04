"""Reference OpenID Connect provider backed by did:home proofs.

"Login with Vouch": the user signs a login statement with their root key, the
bridge checks it against the static registry and issues an EdDSA-signed ID
token. A reference implementation, not yet tested with real relying parties.
The ID token says who logged in (the handle), nothing more.

Run it:

    python -m vouch.oidc --registry ./registry --client myapp=https://app/cb

Endpoints: /.well-known/openid-configuration, /jwks.json, /authorize (GET
shows the statement to sign, POST takes the proof), /token, /userinfo.
Authorization code flow with PKCE (S256) only; deny by default.

Behind a reverse proxy, pass ``--trusted-proxy CIDR`` so rate limits key on
the client address from ``X-Forwarded-For`` rather than the proxy's.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import math
import secrets
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from capgate.didhome.cli import decode_key, encode_key, write_secret
from capgate.didhome.proof import ProofError, verify_proof_for_handle
from capgate.didhome.registry import Registry, RegistryError

PROOF_MAX_AGE_SECONDS = 300
PROOF_MAX_FUTURE_SKEW_SECONDS = 30
NONCE_TTL_SECONDS = 2 * PROOF_MAX_AGE_SECONDS
CODE_TTL_SECONDS = 120
TOKEN_TTL_SECONDS = 3600
RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RATE_LIMITS = {"begin": 20, "authorize": 20, "token": 30, "userinfo": 60}
MAX_RATE_LIMIT_BUCKETS = 10_000
MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_PENDING_CODES = 10_000
MAX_SEEN_NONCES = 100_000
MAX_ACCESS_TOKENS = 100_000
REQUEST_TIMEOUT_SECONDS = 10
MAX_CONCURRENT_CONNECTIONS = 64


class OIDCError(ValueError):
    """Raised on a rejected OIDC request."""


class RateLimitError(OIDCError):
    """Raised when an OIDC endpoint's rate limit has been exceeded."""

    def __init__(self, endpoint: str, retry_after: float) -> None:
        self.retry_after = max(1, math.ceil(retry_after))
        super().__init__(f"rate limit exceeded for {endpoint}")


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
    code_challenge: str = ""


@dataclass
class _Pending:
    """A GET /authorize request waiting for its signed login proof."""

    client_id: str
    redirect_uri: str
    state: str
    nonce: str
    code_challenge: str
    expires_at: float


def pkce_s256(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _valid_pkce_value(value: str) -> bool:
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    return 43 <= len(value) <= 128 and set(value) <= allowed


def load_or_create_signing_key(path: str | Path) -> Ed25519PrivateKey:
    """The bridge's ID-token key, kept across restarts in a 0600 file."""
    path = Path(path)
    if path.exists():
        return decode_key(path.read_text(encoding="utf-8"), None)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    write_secret(path, encode_key(key, None))
    return key


@dataclass
class OIDCProvider:
    """The bridge: did:home proof in, standard OIDC tokens out."""

    registry: Registry
    issuer: str = "http://localhost:9000"
    clients: dict[str, str] = field(default_factory=dict)  # client_id -> redirect_uri
    # client_id -> secret. Listed clients must authenticate at /token.
    client_secrets: dict[str, str] = field(default_factory=dict)
    signing_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    _codes: dict[str, _Code] = field(default_factory=dict)
    _pending: dict[str, _Pending] = field(default_factory=dict)
    _access_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    _seen_proof_nonces: dict[tuple[str, str], float] = field(default_factory=dict)
    rate_limit_window_seconds: int = RATE_LIMIT_WINDOW_SECONDS
    rate_limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_RATE_LIMITS))
    _rate_events: OrderedDict[tuple[str, str], list[float]] = field(default_factory=OrderedDict)
    # The HTTP server is threaded; every entry point takes this lock.
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

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
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            "scopes_supported": ["openid"],
            "claims_supported": ["sub", "handle", "preferred_username"],
        }

    def jwks(self) -> dict[str, Any]:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": _b64url(raw)}]}

    # -- authorization code flow -------------------------------------------

    def login_statement(self, client_id: str, challenge: str = "") -> str:
        """What the user signs (with ``vouch-id card``) to log in.

        Bound to this issuer and the client, and to the server's one-time
        challenge when the login started at GET /authorize.
        """
        statement = f"login:{client_id}@{self.issuer}"
        return f"{statement}#{challenge}" if challenge else statement

    def _sweep(self, current: float) -> None:
        """Drop expired codes, access tokens and replay nonces."""
        for code in [c for c, g in self._codes.items() if current > g.expires_at]:
            del self._codes[code]
        for token in [t for t, info in self._access_tokens.items() if current > info["expires_at"]]:
            del self._access_tokens[token]
        for key in [k for k, exp in self._seen_proof_nonces.items() if current > exp]:
            del self._seen_proof_nonces[key]
        for challenge in [c for c, p in self._pending.items() if current > p.expires_at]:
            del self._pending[challenge]

    def _consume_rate_limit(self, endpoint: str, limiter_key: str, current: float) -> None:
        with self._lock:
            self._consume_rate_limit_locked(endpoint, limiter_key, current)

    def _consume_rate_limit_locked(self, endpoint: str, limiter_key: str, current: float) -> None:
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
            raise RateLimitError(endpoint, events[0] + self.rate_limit_window_seconds - current)
        if not limit:
            return
        events.append(current)
        self._rate_events[bucket_key] = events
        while len(self._rate_events) > MAX_RATE_LIMIT_BUCKETS:
            self._rate_events.popitem(last=False)

    def begin(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state: str = "",
        nonce: str = "",
        now: float | None = None,
    ) -> str:
        """Start a login (GET /authorize). Returns the one-time challenge."""
        current = time.time() if now is None else now
        with self._lock:
            self._sweep(current)
            if self.clients.get(client_id) != redirect_uri:
                raise OIDCError("unknown client_id or redirect_uri mismatch")
            if code_challenge_method != "S256" or not _valid_pkce_value(code_challenge):
                raise OIDCError("PKCE with code_challenge_method=S256 is required")
            if len(self._pending) >= MAX_PENDING_CODES:
                raise OIDCError("too many pending logins, try again later")
            challenge = secrets.token_urlsafe(16)
            self._pending[challenge] = _Pending(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                expires_at=current + PROOF_MAX_AGE_SECONDS,
            )
            return challenge

    def complete(
        self,
        challenge: str,
        proof: dict[str, Any],
        now: float | None = None,
        limiter_key: str | None = None,
    ) -> tuple[str, str]:
        """Finish a login (POST /authorize). Returns (code, redirect URL).

        Pass ``limiter_key`` to charge the authorize rate limit here; the HTTP
        server charges it before reading the body and passes None.
        """
        current = time.time() if now is None else now
        if limiter_key is not None:
            self._consume_rate_limit("authorize", limiter_key or "global", current)
        with self._lock:
            self._sweep(current)
            request = self._pending.get(challenge)
            if request is None:
                raise OIDCError("unknown or expired login request")
            code = self._authorize_locked(
                request.client_id,
                request.redirect_uri,
                proof,
                request.nonce,
                current,
                code_challenge=request.code_challenge,
                challenge=challenge,
            )
            del self._pending[challenge]
        params = {"code": code}
        if request.state:
            params["state"] = request.state
        return code, _redirect_url(request.redirect_uri, params)

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        proof: dict[str, Any],
        nonce: str = "",
        now: float | None = None,
        limiter_key: str = "",
        code_challenge: str = "",
    ) -> str:
        """Validate a did:home login proof directly; return a one-time code."""
        current = time.time() if now is None else now
        self._consume_rate_limit("authorize", limiter_key or client_id, current)
        with self._lock:
            return self._authorize_locked(
                client_id, redirect_uri, proof, nonce, current, code_challenge=code_challenge
            )

    def _authorize_locked(
        self,
        client_id: str,
        redirect_uri: str,
        proof: dict[str, Any],
        nonce: str,
        current: float,
        code_challenge: str = "",
        challenge: str = "",
    ) -> str:
        self._sweep(current)
        if self.clients.get(client_id) != redirect_uri:
            raise OIDCError("unknown client_id or redirect_uri mismatch")
        try:
            manifest = verify_proof_for_handle(proof, self.registry)
        except (RegistryError, ProofError, ValueError) as exc:
            raise OIDCError(f"login proof rejected: {exc}") from exc
        if proof.get("statement") != self.login_statement(client_id, challenge):
            raise OIDCError("proof statement does not authorize this client")
        issued_at = proof.get("issued_at")
        # bool is an int subclass; floats (including NaN and inf) are refused.
        if type(issued_at) is not int:
            raise OIDCError("login proof issued_at must be an integer")
        if issued_at > current + PROOF_MAX_FUTURE_SKEW_SECONDS:
            raise OIDCError("login proof issued in the future")
        if current - issued_at > PROOF_MAX_AGE_SECONDS:
            raise OIDCError("login proof expired")
        proof_nonce = proof.get("nonce")
        if not isinstance(proof_nonce, str) or not proof_nonce:
            raise OIDCError("login proof nonce missing")
        nonce_key = (manifest.handle, proof_nonce)
        if nonce_key in self._seen_proof_nonces:
            raise OIDCError("login proof replayed")
        if len(self._seen_proof_nonces) >= MAX_SEEN_NONCES:
            raise OIDCError("too many recent logins, try again later")
        if len(self._codes) >= MAX_PENDING_CODES:
            raise OIDCError("too many pending logins, try again later")
        self._seen_proof_nonces[nonce_key] = current + NONCE_TTL_SECONDS
        code = secrets.token_urlsafe(24)
        self._codes[code] = _Code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            did=manifest.did,
            handle=manifest.handle,
            nonce=nonce,
            expires_at=current + CODE_TTL_SECONDS,
            code_challenge=code_challenge,
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
        code_verifier: str = "",
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        """Exchange a one-time code for an EdDSA-signed ID token."""
        current = time.time() if now is None else now
        self._consume_rate_limit("token", limiter_key or client_id, current)
        with self._lock:
            return self._token_locked(
                grant_type, code, client_id, redirect_uri, current, code_verifier, client_secret
            )

    def _token_locked_entry(self, *args: Any) -> dict[str, Any]:
        with self._lock:
            return self._token_locked(*args)

    def _token_locked(
        self,
        grant_type: str,
        code: str,
        client_id: str,
        redirect_uri: str,
        current: float,
        code_verifier: str = "",
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        self._sweep(current)
        if grant_type != "authorization_code":
            raise OIDCError("unsupported grant_type")
        expected_secret = self.client_secrets.get(client_id)
        if expected_secret is not None and not hmac.compare_digest(
            (client_secret or "").encode(), expected_secret.encode()
        ):
            raise OIDCError("client authentication failed")
        grant = self._codes.pop(code, None)
        if grant is None or current > grant.expires_at:
            raise OIDCError("invalid or expired code")
        if grant.client_id != client_id or grant.redirect_uri != redirect_uri:
            raise OIDCError("code was issued to a different client")
        if grant.code_challenge and not hmac.compare_digest(
            pkce_s256(code_verifier).encode(), grant.code_challenge.encode()
        ):
            raise OIDCError("PKCE code_verifier does not match")
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
        while len(self._access_tokens) >= MAX_ACCESS_TOKENS:
            # Evict the oldest token; that session has to log in again.
            del self._access_tokens[next(iter(self._access_tokens))]
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
        with self._lock:
            self._consume_rate_limit_locked("userinfo", limiter_key or "bearer", current)
            self._sweep(current)
            return self._userinfo_locked(authorization, current)

    def _userinfo_locked(self, authorization: str, current: float) -> dict[str, Any]:
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


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _is_trusted(text: str, trusted: Sequence[Network]) -> bool:
    addr = _parse_ip(text)
    return addr is not None and any(addr in net for net in trusted)


def forwarded_client(peer: str, forwarded_for: Sequence[str], trusted: Sequence[Network]) -> str:
    """The client address to rate-limit on.

    ``X-Forwarded-For`` is only read when the socket peer is a trusted proxy.
    Then the rightmost hop that is not itself a trusted proxy is the client:
    hops to its left were supplied by the client and can be forged.
    """
    if not _is_trusted(peer, trusted):
        return peer
    hops = [h.strip() for value in forwarded_for for h in value.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _is_trusted(hop, trusted):
            addr = _parse_ip(hop)
            return str(addr) if addr is not None else hop
    return hops[0] if hops else peer


def trusted_proxy_limiter_key(
    trusted: Sequence[Network],
) -> Callable[[BaseHTTPRequestHandler], str]:
    """Limiter-key callback for ``_make_handler`` behind trusted proxies."""

    def key(request: BaseHTTPRequestHandler) -> str:
        return forwarded_client(
            request.client_address[0],
            request.headers.get_all("X-Forwarded-For") or [],
            trusted,
        )

    return key


def _redirect_url(redirect_uri: str, params: dict[str, str]) -> str:
    sep = "&" if urlparse(redirect_uri).query else "?"
    return redirect_uri + sep + urlencode(params)


_LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Log in with Vouch</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 2rem auto">
<h1>Log in to {client}</h1>
<p>Sign this statement with your Vouch key:</p>
<pre>{command}</pre>
<p>Paste the JSON it prints below. It works once, for the next five minutes.</p>
<form method="post" action="/authorize">
<input type="hidden" name="challenge" value="{challenge}">
<textarea name="proof" rows="12" cols="70" required></textarea><br>
<button type="submit">Log in</button>
</form></body></html>
"""


def login_page(provider: OIDCProvider, client_id: str, challenge: str) -> str:
    statement = provider.login_statement(client_id, challenge)
    command = f"vouch-id card @yourname --json --statement '{statement}'"
    return _LOGIN_PAGE.format(
        client=html.escape(client_id),
        command=html.escape(command),
        challenge=html.escape(challenge),
    )


def _client_auth(headers: Any, form: dict[str, str]) -> tuple[str, str | None]:
    """client_id and secret from HTTP Basic or the form (RFC 6749 2.3.1)."""
    auth = headers.get("Authorization", "")
    if auth.startswith("Basic "):
        from urllib.parse import unquote

        try:
            user, _, secret = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError) as exc:
            raise OIDCError("malformed Basic authorization") from exc
        return unquote(user), unquote(secret)
    return form.get("client_id", ""), form.get("client_secret")


def _make_handler(
    provider: OIDCProvider,
    limiter_key: Callable[[BaseHTTPRequestHandler], str] | None = None,
    request_timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> type[BaseHTTPRequestHandler]:
    """Build a handler with an optional trusted client-identity callback."""

    class Handler(BaseHTTPRequestHandler):
        # Socket timeout: a client that stalls mid-request is dropped.
        timeout = request_timeout

        def _send(
            self,
            status: int,
            body: dict[str, Any],
            headers: dict[str, str] | None = None,
        ) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def _send_html(self, status: int, page: str) -> None:
            data = page.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _rate_limit_key(self) -> str:
            return limiter_key(self) if limiter_key else self.client_address[0]

        def do_GET(self) -> None:
            url = urlparse(self.path)
            path = url.path
            if path == "/authorize":
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                try:
                    provider._consume_rate_limit("begin", self._rate_limit_key(), time.time())
                    if query.get("response_type") != "code":
                        raise OIDCError("response_type=code is required")
                    if "openid" not in query.get("scope", "").split():
                        raise OIDCError("scope must include openid")
                    challenge = provider.begin(
                        query.get("client_id", ""),
                        query.get("redirect_uri", ""),
                        query.get("code_challenge", ""),
                        query.get("code_challenge_method", ""),
                        state=query.get("state", ""),
                        nonce=query.get("nonce", ""),
                    )
                except RateLimitError as exc:
                    self._send(429, {"error": str(exc)}, {"Retry-After": str(exc.retry_after)})
                    return
                except OIDCError as exc:
                    # Never redirect on a bad client or redirect_uri.
                    self._send(400, {"error": str(exc)})
                    return
                self._send_html(200, login_page(provider, query["client_id"], challenge))
            elif path == "/.well-known/openid-configuration":
                self._send(200, provider.discovery())
            elif path == "/jwks.json":
                self._send(200, provider.jwks())
            elif path == "/userinfo":
                try:
                    self._send(
                        200,
                        provider.userinfo(
                            self.headers.get("Authorization", ""),
                            limiter_key=self._rate_limit_key(),
                        ),
                    )
                except RateLimitError as exc:
                    self._send(
                        429,
                        {"error": str(exc)},
                        {"Retry-After": str(exc.retry_after)},
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
                provider._consume_rate_limit(endpoint, self._rate_limit_key(), current)
            except RateLimitError as exc:
                self._send(
                    429,
                    {"error": str(exc)},
                    {"Retry-After": str(exc.retry_after)},
                )
                return
            except OIDCError as exc:
                self._send(400, {"error": str(exc)})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0:
                    raise OIDCError("invalid Content-Length")
                if length > MAX_REQUEST_BODY_BYTES:
                    self._send(413, {"error": "request body too large"})
                    return
                raw = self.rfile.read(length).decode("utf-8")
                content_type = self.headers.get("Content-Type", "")
                if endpoint == "authorize":
                    if content_type.startswith("application/json"):
                        body = json.loads(raw)
                        if not isinstance(body, dict):
                            raise OIDCError("expected a JSON object")
                        code, location = provider.complete(
                            str(body["challenge"]), body["proof"], current
                        )
                        self._send(200, {"code": code, "redirect": location})
                    else:
                        form = {k: v[0] for k, v in parse_qs(raw).items()}
                        proof = json.loads(form["proof"])
                        _, location = provider.complete(form["challenge"], proof, current)
                        self._redirect(location)
                else:
                    form = {k: v[0] for k, v in parse_qs(raw).items()}
                    client_id, client_secret = _client_auth(self.headers, form)
                    if form.get("client_id") and form["client_id"] != client_id:
                        raise OIDCError("client_id does not match client authentication")
                    tokens = provider._token_locked_entry(
                        form.get("grant_type", ""),
                        form.get("code", ""),
                        client_id,
                        form.get("redirect_uri", ""),
                        current,
                        form.get("code_verifier", ""),
                        client_secret,
                    )
                    self._send(200, tokens, {"Cache-Control": "no-store", "Pragma": "no-cache"})
            except RateLimitError as exc:
                self._send(
                    429,
                    {"error": str(exc)},
                    {"Retry-After": str(exc.retry_after)},
                )
            except (OIDCError, KeyError, TypeError, ValueError) as exc:
                self._send(400, {"error": str(exc)})

        def log_message(self, *args: Any) -> None:  # quiet by default
            pass

    return Handler


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """One thread per connection, capped; extra connections are closed."""

    daemon_threads = True

    def __init__(self, *args: Any, max_connections: int, **kwargs: Any) -> None:
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(
    provider: OIDCProvider,
    host: str = "127.0.0.1",
    port: int = 9000,
    limiter_key: Callable[[BaseHTTPRequestHandler], str] | None = None,
    request_timeout: float = REQUEST_TIMEOUT_SECONDS,
    max_connections: int = MAX_CONCURRENT_CONNECTIONS,
) -> ThreadingHTTPServer:
    """Threaded HTTP server for the bridge with a per-request socket timeout."""
    return _BoundedThreadingHTTPServer(
        (host, port),
        _make_handler(provider, limiter_key, request_timeout),
        max_connections=max_connections,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vouch-oidc",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--registry", default="./registry")
    parser.add_argument(
        "--issuer", default=None, help="public base URL (default: http://localhost:PORT)"
    )
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--signing-key",
        default=str(Path.home() / ".didhome" / "oidc-signing.key"),
        help="ID-token signing key, created at 0600 if missing (default: %(default)s)",
    )
    parser.add_argument(
        "--client-secret-file",
        action="append",
        default=[],
        metavar="CLIENT_ID=PATH",
        help="require this client to authenticate at /token with the secret in PATH",
    )
    parser.add_argument(
        "--client",
        action="append",
        default=[],
        help="client_id=redirect_uri (repeatable)",
        required=True,
    )
    parser.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        metavar="CIDR",
        help="reverse proxy address range whose X-Forwarded-For is trusted for "
        "rate limiting (repeatable); default: key on the socket peer",
    )
    args = parser.parse_args(argv)
    try:
        trusted = [ipaddress.ip_network(c, strict=False) for c in args.trusted_proxy]
    except ValueError as exc:
        parser.error(f"--trusted-proxy: {exc}")
    try:
        clients = dict(item.split("=", 1) for item in args.client)
        secret_files = dict(item.split("=", 1) for item in args.client_secret_file)
    except ValueError:
        parser.error("--client and --client-secret-file take NAME=VALUE")
    client_secrets = {
        cid: Path(path).read_text(encoding="utf-8").strip() for cid, path in secret_files.items()
    }
    unknown = set(client_secrets) - set(clients)
    if unknown:
        parser.error(f"--client-secret-file for unknown client: {', '.join(sorted(unknown))}")
    issuer = (args.issuer or f"http://localhost:{args.port}").rstrip("/")
    registry = Registry(args.registry)
    try:
        count = registry.verify()
    except (RegistryError, ValueError) as exc:
        print(f"registry failed verification, not starting: {exc}", file=sys.stderr)
        return 1
    print(f"registry verified ({count} events)")
    provider = OIDCProvider(
        registry,
        issuer=issuer,
        clients=clients,
        client_secrets=client_secrets,
        signing_key=load_or_create_signing_key(args.signing_key),
    )
    server = make_server(
        provider,
        port=args.port,
        limiter_key=trusted_proxy_limiter_key(trusted) if trusted else None,
    )
    print(f"vouch OIDC bridge on {issuer} (clients: {', '.join(clients)})")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
