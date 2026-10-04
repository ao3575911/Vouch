"""Offline proofs, printable cards, and the OIDC bridge."""

import base64
import ipaddress
import json
import math
import re
import socket
import time
from http.client import HTTPConnection
from http.server import HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.manifest import _canonical_json, create_manifest, public_key_hex
from capgate.didhome.proof import (
    ProofError,
    card_html,
    create_proof,
    verify_proof,
    verify_proof_for_handle,
)
from capgate.didhome.registry import Registry, RegistryError
from vouch.oidc import (
    MAX_REQUEST_BODY_BYTES,
    OIDCError,
    OIDCProvider,
    _make_handler,
    decode_jwt,
    forwarded_client,
    load_or_create_signing_key,
    main,
    make_server,
    pkce_s256,
    trusted_proxy_limiter_key,
)


@pytest.fixture
def world(tmp_path):
    registry = Registry(tmp_path / "registry")
    key = Ed25519PrivateKey.generate()
    registry.claim(create_manifest("adam", key), key)
    return registry, key


# -- proofs + cards ---------------------------------------------------------


def test_proof_roundtrip(world):
    registry, key = world
    manifest = registry.resolve("adam")
    proof = create_proof(manifest, key, "this is my name")
    verify_proof(proof, expected_public_key=manifest.root_public_key)


def test_tampered_proof_rejected(world):
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "over 18")
    proof["statement"] = "over 21"
    with pytest.raises(ProofError, match="invalid"):
        verify_proof(proof)


def test_proof_from_wrong_key_rejected(world):
    registry, key = world
    manifest = registry.resolve("adam")
    proof = create_proof(manifest, key, "hi")
    with pytest.raises(ProofError, match="unexpected key"):
        verify_proof(proof, expected_public_key="00" * 32)


def _forged_adam():
    """An attacker's self-signed manifest and proof for @adam under their own key."""
    attacker = Ed25519PrivateKey.generate()
    fake = create_manifest("adam", attacker)
    return fake, attacker


def test_forged_key_proof_rejected_when_pinned(world):
    registry, _ = world
    fake, attacker = _forged_adam()
    proof = create_proof(fake, attacker, "I am @adam")
    verify_proof(proof)  # self-asserted: the key in the proof did sign it
    with pytest.raises(ProofError, match="unexpected key"):
        verify_proof_for_handle(proof, registry)


def test_pinned_proof_accepted(world):
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "this is my name")
    assert verify_proof_for_handle(proof, registry).did == "did:home:adam"


def test_did_handle_mismatch_rejected(world):
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "hi")
    proof["did"] = "did:home:eve"
    unsigned = {k: v for k, v in proof.items() if k != "signature"}
    proof["signature"] = key.sign(_canonical_json(unsigned)).hex()
    with pytest.raises(ProofError, match="did does not match handle"):
        verify_proof(proof)
    with pytest.raises(ProofError, match="did does not match handle"):
        verify_proof_for_handle(proof, registry)


def test_unknown_handle_rejected_when_pinned(world):
    registry, _ = world
    key = Ed25519PrivateKey.generate()
    proof = create_proof(create_manifest("nobody", key), key, "hi")
    with pytest.raises(ProofError, match="not resolvable"):
        verify_proof_for_handle(proof, registry)


def _swap_names_file(registry, manifest):
    (registry.names_dir / f"{manifest.handle}.json").write_text(
        json.dumps(manifest.to_dict()), encoding="utf-8"
    )


def test_resolve_rejects_swapped_manifest(world):
    registry, _ = world
    fake, _ = _forged_adam()
    _swap_names_file(registry, fake)
    with pytest.raises(RegistryError):
        registry.resolve("adam")


def test_resolve_rejects_names_file_for_other_handle(world):
    registry, _ = world
    eve_key = Ed25519PrivateKey.generate()
    registry.claim(create_manifest("eve", eve_key), eve_key)
    (registry.names_dir / "adam.json").write_text(
        (registry.names_dir / "eve.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    with pytest.raises(RegistryError, match="another handle"):
        registry.resolve("adam")


def test_card_html_embeds_proof(world):
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "this is my name")
    page = card_html(proof)
    assert "@adam" in page
    assert proof["signature"] in page


def test_proof_issued_at_is_int_for_browser_canonical_json(world):
    """docs/verify.html re-canonicalises in JS; ints serialise identically."""
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "x")
    assert isinstance(proof["issued_at"], int)
    json.dumps(proof)  # round-trippable


# -- OIDC bridge ------------------------------------------------------------

CLIENT = "myapp"
REDIRECT = "https://app.example/cb"


@pytest.fixture
def provider(world):
    registry, _ = world
    return OIDCProvider(registry, issuer="https://vouch.example", clients={CLIENT: REDIRECT})


def _serve(server):
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _stop(server, thread):
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def oidc_http_server(provider):
    server = make_server(provider, port=0)
    thread = _serve(server)
    yield server.server_address
    _stop(server, thread)


def _login_proof(world, provider, statement=None):
    registry, key = world
    return create_proof(
        registry.resolve("adam"), key, statement or provider.login_statement(CLIENT)
    )


def test_full_code_flow(world, provider):
    code = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), nonce="n1")
    tokens = provider.token("authorization_code", code, CLIENT, REDIRECT)
    claims = decode_jwt(tokens["id_token"], provider.signing_key.public_key())
    assert claims["sub"] == "did:home:adam"
    assert claims["aud"] == CLIENT
    assert claims["nonce"] == "n1"
    assert claims["preferred_username"] == "@adam"
    info = provider.userinfo("Bearer " + tokens["access_token"])
    assert info["handle"] == "adam"


def test_authorize_rejects_forged_key_proof(provider):
    fake, attacker = _forged_adam()
    proof = create_proof(fake, attacker, provider.login_statement(CLIENT))
    with pytest.raises(OIDCError, match="unexpected key"):
        provider.authorize(CLIENT, REDIRECT, proof)


def test_authorize_rejects_swapped_manifest(world, provider):
    registry, _ = world
    fake, attacker = _forged_adam()
    _swap_names_file(registry, fake)
    proof = create_proof(fake, attacker, provider.login_statement(CLIENT))
    with pytest.raises(OIDCError, match="login proof rejected"):
        provider.authorize(CLIENT, REDIRECT, proof)


def test_bridge_refuses_to_start_on_unverified_registry(world, capsys):
    registry, _ = world
    fake, _ = _forged_adam()
    _swap_names_file(registry, fake)
    assert main(["--registry", str(registry.root), "--client", f"{CLIENT}={REDIRECT}"]) == 1
    assert "not starting" in capsys.readouterr().err


def test_discovery_and_jwks(provider):
    disco = provider.discovery()
    assert disco["issuer"] == "https://vouch.example"
    assert disco["id_token_signing_alg_values_supported"] == ["EdDSA"]
    jwk = provider.jwks()["keys"][0]
    assert (jwk["kty"], jwk["crv"]) == ("OKP", "Ed25519")


def test_unknown_client_denied(world, provider):
    with pytest.raises(OIDCError, match="client_id"):
        provider.authorize("evilapp", REDIRECT, _login_proof(world, provider))


def test_proof_for_other_client_denied(world, provider):
    proof = _login_proof(world, provider, statement="login:otherapp")
    with pytest.raises(OIDCError, match="does not authorize"):
        provider.authorize(CLIENT, REDIRECT, proof)


def test_stale_proof_denied(world, provider):
    registry, key = world
    proof = create_proof(
        registry.resolve("adam"), key, provider.login_statement(CLIENT), now=1000.0
    )
    with pytest.raises(OIDCError, match="expired"):
        provider.authorize(CLIENT, REDIRECT, proof, now=100000.0)


def test_proof_replay_denied(world, provider):
    proof = _login_proof(world, provider)
    provider.authorize(CLIENT, REDIRECT, proof)
    with pytest.raises(OIDCError, match="replayed"):
        provider.authorize(CLIENT, REDIRECT, proof)


def test_code_single_use_and_client_bound(world, provider):
    code = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider))
    provider.token("authorization_code", code, CLIENT, REDIRECT)
    with pytest.raises(OIDCError, match="invalid or expired"):
        provider.token("authorization_code", code, CLIENT, REDIRECT)
    code2 = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider))
    with pytest.raises(OIDCError, match="different client"):
        provider.token("authorization_code", code2, "evilapp", REDIRECT)


def test_forged_jwt_rejected(world, provider):
    code = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider))
    tokens = provider.token("authorization_code", code, CLIENT, REDIRECT)
    with pytest.raises(OIDCError, match="invalid JWT"):
        decode_jwt(tokens["id_token"], Ed25519PrivateKey.generate().public_key())


def test_userinfo_requires_valid_bearer(provider):
    with pytest.raises(OIDCError, match="bearer"):
        provider.userinfo("")
    with pytest.raises(OIDCError, match="invalid or expired"):
        provider.userinfo("Bearer " + "nope")


def test_authorize_rate_limited(world, provider):
    provider.rate_limits["authorize"] = 2
    provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip1")
    provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip1")
    with pytest.raises(OIDCError, match="rate limit exceeded for authorize"):
        provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip1")


def test_token_rate_limited(world, provider):
    provider.rate_limits["token"] = 1
    code1 = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip2")
    provider.token("authorization_code", code1, CLIENT, REDIRECT, limiter_key="ip2")
    code2 = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip2")
    with pytest.raises(OIDCError, match="rate limit exceeded for token"):
        provider.token("authorization_code", code2, CLIENT, REDIRECT, limiter_key="ip2")


def test_userinfo_rate_limited(world, provider):
    provider.rate_limits["userinfo"] = 1
    code = provider.authorize(CLIENT, REDIRECT, _login_proof(world, provider), limiter_key="ip3")
    tokens = provider.token("authorization_code", code, CLIENT, REDIRECT, limiter_key="ip3")
    provider.userinfo("Bearer " + tokens["access_token"], limiter_key="ip3")
    with pytest.raises(OIDCError, match="rate limit exceeded for userinfo"):
        provider.userinfo("Bearer " + tokens["access_token"], limiter_key="ip3")


def test_rate_limit_evicts_inactive_buckets(provider):
    provider._consume_rate_limit("authorize", "ip1", 0)
    provider._consume_rate_limit("authorize", "ip2", 61)
    assert ("authorize", "ip1") not in provider._rate_events


def test_rate_limit_bucket_count_is_bounded(provider, monkeypatch):
    monkeypatch.setattr("vouch.oidc.MAX_RATE_LIMIT_BUCKETS", 2)
    for key in ("ip1", "ip2", "ip3"):
        provider._consume_rate_limit("authorize", key, 1)
    assert len(provider._rate_events) == 2
    assert ("authorize", "ip1") not in provider._rate_events


def test_authorize_http_rate_limit_counts_invalid_requests(oidc_http_server, provider):
    provider.rate_limits["authorize"] = 2
    connection = HTTPConnection(*oidc_http_server)
    for body in ("{", "{}"):
        connection.request("POST", "/authorize", body)
        response = connection.getresponse()
        response.read()
        assert response.status == 400
    connection.request("POST", "/authorize", "{}")
    response = connection.getresponse()
    assert json.loads(response.read())["error"] == "rate limit exceeded for authorize"
    connection.close()


def _begin(provider, verifier="v" * 43, state=""):
    challenge = provider.begin(CLIENT, REDIRECT, pkce_s256(verifier), state=state, nonce="n1")
    return challenge, verifier


def test_authorize_http_rate_limit_is_not_double_consumed(world, oidc_http_server, provider):
    provider.rate_limits["authorize"] = 1
    challenge, _ = _begin(provider)
    proof = _login_proof(world, provider, provider.login_statement(CLIENT, challenge))
    connection = HTTPConnection(*oidc_http_server)
    connection.request(
        "POST",
        "/authorize",
        json.dumps({"challenge": challenge, "proof": proof}),
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    assert response.status == 200
    connection.close()


@pytest.mark.parametrize(
    ("endpoint", "method", "path", "body", "first_status"),
    [
        ("authorize", "POST", "/authorize", "{}", 400),
        ("token", "POST", "/token", "", 400),
        ("userinfo", "GET", "/userinfo", None, 401),
    ],
)
def test_http_rate_limits_return_429_with_retry_after(
    provider, oidc_http_server, endpoint, method, path, body, first_status
):
    provider.rate_limits[endpoint] = 1
    connection = HTTPConnection(*oidc_http_server)
    connection.request(method, path, body)
    first_response = connection.getresponse()
    first_response.read()
    assert first_response.status == first_status

    connection.request(method, path, body)
    response = connection.getresponse()
    response.read()
    assert response.status == 429
    assert int(response.getheader("Retry-After")) >= 1
    connection.close()


@pytest.mark.parametrize(
    ("content_length", "expected_status"),
    [
        ("-1", 400),
        (str(MAX_REQUEST_BODY_BYTES + 1), 413),
    ],
)
def test_http_rejects_invalid_or_oversized_content_length(
    oidc_http_server, content_length, expected_status
):
    connection = HTTPConnection(*oidc_http_server, timeout=1)
    connection.request("POST", "/authorize", headers={"Content-Length": content_length})
    response = connection.getresponse()
    response.read()
    assert response.status == expected_status
    connection.close()


def test_http_rate_limit_uses_configured_client_identity(provider):
    provider.rate_limits["authorize"] = 1
    server = HTTPServer(
        ("127.0.0.1", 0),
        _make_handler(
            provider,
            limiter_key=lambda request: request.headers.get("X-Trusted-Client", ""),
        ),
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection(*server.server_address)
    try:
        statuses = []
        for identity in ("client-a", "client-b", "client-a"):
            connection.request(
                "POST",
                "/authorize",
                "{}",
                headers={"X-Trusted-Client": identity},
            )
            response = connection.getresponse()
            response.read()
            statuses.append(response.status)
        assert statuses == [400, 400, 429]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join()


# -- OIDC hardening -----------------------------------------------------------


def _signed_login(world, provider, issued_at, nonce="ab12"):
    """A login proof with an arbitrary issued_at value, correctly signed."""
    registry, key = world
    manifest = registry.resolve("adam")
    proof = {
        "did": manifest.did,
        "handle": manifest.handle,
        "statement": provider.login_statement(CLIENT),
        "public_key": manifest.root_public_key,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    proof["signature"] = key.sign(_canonical_json(proof)).hex()
    return proof


@pytest.mark.parametrize(
    "issued_at", [math.nan, math.inf, -math.inf, "1759550400", 1759550400.0, True, None]
)
def test_non_integer_issued_at_rejected(world, provider, issued_at):
    proof = _signed_login(world, provider, issued_at)
    with pytest.raises(OIDCError, match="issued_at must be an integer"):
        provider.authorize(CLIENT, REDIRECT, proof, now=1759550400)


def test_nan_issued_at_from_json_rejected(world, provider):
    proof = json.loads(json.dumps(_signed_login(world, provider, math.nan)))
    assert math.isnan(proof["issued_at"])
    with pytest.raises(OIDCError, match="integer"):
        provider.authorize(CLIENT, REDIRECT, proof, now=time.time() + 3e7)


def test_future_dated_proof_rejected(world, provider):
    now = 1759550400
    provider.authorize(CLIENT, REDIRECT, _signed_login(world, provider, now + 30, "n1"), now=now)
    with pytest.raises(OIDCError, match="future"):
        provider.authorize(
            CLIENT, REDIRECT, _signed_login(world, provider, now + 31, "n2"), now=now
        )


def test_state_is_swept_after_expiry(world, provider):
    now = 1759550400
    for i in range(50):
        proof = _signed_login(world, provider, now, nonce=f"n{i}")
        code = provider.authorize(CLIENT, REDIRECT, proof, now=now, limiter_key=str(i))
        if i % 2:
            provider.token(
                "authorization_code", code, CLIENT, REDIRECT, now=now, limiter_key=str(i)
            )
    assert len(provider._codes) == 25
    assert len(provider._access_tokens) == 25
    assert len(provider._seen_proof_nonces) == 50
    later = now + 3601
    provider.authorize(CLIENT, REDIRECT, _signed_login(world, provider, later, "fresh"), now=later)
    assert len(provider._codes) == 1
    assert len(provider._access_tokens) == 0
    assert list(provider._seen_proof_nonces) == [("adam", "fresh")]


def test_nonce_replay_blocked_until_proof_expires(world, provider):
    now = 1759550400
    proof = _signed_login(world, provider, now)
    provider.authorize(CLIENT, REDIRECT, proof, now=now)
    with pytest.raises(OIDCError, match="replayed"):
        provider.authorize(CLIENT, REDIRECT, proof, now=now + 300)
    with pytest.raises(OIDCError, match="expired"):
        provider.authorize(CLIENT, REDIRECT, proof, now=now + 301)


def test_pending_code_cap(world, provider, monkeypatch):
    monkeypatch.setattr("vouch.oidc.MAX_PENDING_CODES", 3)
    now = 1759550400
    for i in range(3):
        provider.authorize(
            CLIENT,
            REDIRECT,
            _signed_login(world, provider, now, f"n{i}"),
            now=now,
            limiter_key=str(i),
        )
    with pytest.raises(OIDCError, match="too many pending"):
        provider.authorize(
            CLIENT, REDIRECT, _signed_login(world, provider, now, "n9"), now=now, limiter_key="x"
        )


def test_access_token_cap_evicts_oldest(world, provider, monkeypatch):
    monkeypatch.setattr("vouch.oidc.MAX_ACCESS_TOKENS", 2)
    now = 1759550400
    tokens = []
    for i in range(3):
        code = provider.authorize(
            CLIENT,
            REDIRECT,
            _signed_login(world, provider, now, f"n{i}"),
            now=now,
            limiter_key=str(i),
        )
        tokens.append(
            provider.token(
                "authorization_code", code, CLIENT, REDIRECT, now=now, limiter_key=str(i)
            )["access_token"]
        )
    assert len(provider._access_tokens) == 2
    with pytest.raises(OIDCError, match="invalid or expired"):
        provider.userinfo("Bearer " + tokens[0], now=now)
    assert provider.userinfo("Bearer " + tokens[2], now=now)["handle"] == "adam"


def test_stalled_request_does_not_block_others(provider):
    server = make_server(provider, port=0, request_timeout=1)
    thread = _serve(server)
    stalled = socket.create_connection(server.server_address)
    try:
        stalled.sendall(b"POST /authorize HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{")
        start = time.monotonic()
        connection = HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/.well-known/openid-configuration")
        response = connection.getresponse()
        response.read()
        connection.close()
        assert response.status == 200
        assert time.monotonic() - start < 1
        stalled.settimeout(5)
        assert stalled.recv(1024) == b""  # dropped after the socket timeout
    finally:
        stalled.close()
        _stop(server, thread)


def test_http_redirect_is_url_encoded(world, oidc_http_server, provider):
    state = "a b&c=d#e"
    challenge, _ = _begin(provider, state=state)
    proof = _login_proof(world, provider, provider.login_statement(CLIENT, challenge))
    connection = HTTPConnection(*oidc_http_server)
    connection.request(
        "POST",
        "/authorize",
        urlencode({"challenge": challenge, "proof": json.dumps(proof)}),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = connection.getresponse()
    response.read()
    connection.close()
    assert response.status == 302
    url = urlparse(response.getheader("Location"))
    assert f"{url.scheme}://{url.netloc}{url.path}" == REDIRECT
    query = parse_qs(url.query)
    assert query["state"] == [state]
    assert url.fragment == ""


# -- standard flow: GET /authorize, PKCE, client auth, signing key -------------


def _get(server_address, path):
    connection = HTTPConnection(*server_address)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read().decode()
    connection.close()
    return response, body


def test_get_authorize_shows_statement_and_full_flow(world, oidc_http_server, provider):
    verifier = "x" * 50
    query = urlencode(
        {
            "response_type": "code",
            "scope": "openid",
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "state": "s1",
            "nonce": "n1",
            "code_challenge": pkce_s256(verifier),
            "code_challenge_method": "S256",
        }
    )
    response, page = _get(oidc_http_server, "/authorize?" + query)
    assert response.status == 200
    assert response.getheader("Content-Type").startswith("text/html")
    challenge = re.search(r'name="challenge" value="([^"]+)"', page).group(1)
    statement = provider.login_statement(CLIENT, challenge)
    assert statement in page
    assert statement.startswith(f"login:{CLIENT}@https://vouch.example#")

    code, location = provider.complete(challenge, _login_proof(world, provider, statement))
    assert parse_qs(urlparse(location).query) == {"code": [code], "state": ["s1"]}
    with pytest.raises(OIDCError, match="PKCE"):
        provider.token("authorization_code", code, CLIENT, REDIRECT, code_verifier="y" * 50)
    code, _ = provider.complete(*(_relogin(world, provider, verifier)))
    tokens = provider.token("authorization_code", code, CLIENT, REDIRECT, code_verifier=verifier)
    claims = decode_jwt(tokens["id_token"], provider.signing_key.public_key())
    assert claims["nonce"] == "n1"


def _relogin(world, provider, verifier):
    challenge, _ = _begin(provider, verifier)
    return challenge, _login_proof(world, provider, provider.login_statement(CLIENT, challenge))


@pytest.mark.parametrize(
    "params",
    [
        {"code_challenge_method": "plain"},
        {"code_challenge": ""},
        {"response_type": "token"},
        {"scope": "profile"},
        {"redirect_uri": "https://evil.example/cb"},
    ],
)
def test_get_authorize_rejects_bad_requests(oidc_http_server, params):
    query = {
        "response_type": "code",
        "scope": "openid",
        "client_id": CLIENT,
        "redirect_uri": REDIRECT,
        "code_challenge": pkce_s256("v" * 43),
        "code_challenge_method": "S256",
    } | params
    response, _ = _get(oidc_http_server, "/authorize?" + urlencode(query))
    assert response.status == 400
    assert response.getheader("Location") is None


def test_challenge_is_single_use_and_bound(world, provider):
    challenge, _ = _begin(provider)
    other, _ = _begin(provider)
    with pytest.raises(OIDCError, match="statement"):
        provider.complete(
            other, _login_proof(world, provider, provider.login_statement(CLIENT, challenge))
        )
    provider.complete(
        challenge, _login_proof(world, provider, provider.login_statement(CLIENT, challenge))
    )
    with pytest.raises(OIDCError, match="unknown or expired"):
        provider.complete(
            challenge, _login_proof(world, provider, provider.login_statement(CLIENT, challenge))
        )


def test_login_proof_for_another_issuer_is_rejected(world, provider):
    proof = _login_proof(world, provider, f"login:{CLIENT}@https://other.example")
    with pytest.raises(OIDCError, match="statement"):
        provider.authorize(CLIENT, REDIRECT, proof)


def test_confidential_client_must_authenticate(world, oidc_http_server, provider):
    provider.client_secrets[CLIENT] = "s3cret"
    challenge, verifier = _begin(provider)
    code, _ = provider.complete(*(_relogin(world, provider, verifier)))
    del challenge

    def post(headers, form):
        connection = HTTPConnection(*oidc_http_server)
        connection.request("POST", "/token", urlencode(form), headers=headers)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
    }
    status, body = post({}, form | {"client_id": CLIENT, "client_secret": "wrong"})
    assert status == 400 and "authentication" in body["error"]
    basic = base64.b64encode(f"{CLIENT}:s3cret".encode()).decode()
    status, body = post({"Authorization": "Basic " + basic}, form)
    assert status == 200 and "id_token" in body


def test_discovery_advertises_pkce(provider):
    disco = provider.discovery()
    assert disco["code_challenge_methods_supported"] == ["S256"]
    assert "client_secret_basic" in disco["token_endpoint_auth_methods_supported"]


def test_signing_key_persists_at_0600(tmp_path):
    path = tmp_path / "oidc.key"
    first = load_or_create_signing_key(path)
    assert path.stat().st_mode & 0o777 == 0o600
    second = load_or_create_signing_key(path)
    assert public_key_hex(first.public_key()) == public_key_hex(second.public_key())


def test_issuer_follows_port(world, tmp_path, monkeypatch, capsys):
    registry, _ = world
    seen = {}

    class FakeServer:
        def serve_forever(self):
            pass

    def fake_make_server(provider, **kwargs):
        seen["issuer"] = provider.issuer
        return FakeServer()

    monkeypatch.setattr("vouch.oidc.make_server", fake_make_server)
    args = ["--registry", str(registry.root), "--port", "9123", "--client", f"{CLIENT}={REDIRECT}"]
    args += ["--signing-key", str(tmp_path / "k")]
    assert main(args) == 0
    assert seen["issuer"] == "http://localhost:9123"


# -- trusted proxy limiter key ------------------------------------------------

LOOPBACK = [ipaddress.ip_network("127.0.0.1/32")]


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.9", ["198.51.100.1"], "203.0.113.9"),  # untrusted peer: XFF ignored
        ("127.0.0.1", [], "127.0.0.1"),  # trusted peer, no XFF
        ("127.0.0.1", ["198.51.100.1"], "198.51.100.1"),
        ("127.0.0.1", ["6.6.6.6, 198.51.100.1"], "198.51.100.1"),  # left hop is spoofable
        ("127.0.0.1", ["6.6.6.6", "198.51.100.1, 127.0.0.1"], "198.51.100.1"),
        ("127.0.0.1", ["127.0.0.1"], "127.0.0.1"),  # every hop trusted
        ("::ffff:127.0.0.1", ["198.51.100.1"], "198.51.100.1"),
    ],
)
def test_forwarded_client(peer, xff, expected):
    assert forwarded_client(peer, xff, LOOPBACK) == expected


def _limited_statuses(provider, trusted, forwarded):
    provider.rate_limits["authorize"] = 1
    server = make_server(provider, port=0, limiter_key=trusted_proxy_limiter_key(trusted))
    thread = _serve(server)
    connection = HTTPConnection(*server.server_address)
    try:
        statuses = []
        for value in forwarded:
            connection.request("POST", "/authorize", "{}", headers={"X-Forwarded-For": value})
            response = connection.getresponse()
            response.read()
            statuses.append(response.status)
        return statuses
    finally:
        connection.close()
        _stop(server, thread)


def test_trusted_proxy_gives_per_client_buckets(provider):
    statuses = _limited_statuses(provider, LOOPBACK, ["198.51.100.1", "198.51.100.2"])
    assert statuses == [400, 400]


def test_spoofed_forwarded_for_from_untrusted_peer_ignored(provider):
    trusted = [ipaddress.ip_network("10.0.0.0/8")]
    statuses = _limited_statuses(provider, trusted, ["198.51.100.1", "198.51.100.2"])
    assert statuses == [400, 429]


def test_main_rejects_bad_trusted_proxy(world):
    registry, _ = world
    with pytest.raises(SystemExit):
        main(
            [
                "--registry",
                str(registry.root),
                "--client",
                f"{CLIENT}={REDIRECT}",
                "--trusted-proxy",
                "not-a-cidr",
            ]
        )
