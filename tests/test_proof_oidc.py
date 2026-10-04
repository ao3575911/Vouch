"""Offline proofs, printable cards, and the OIDC bridge."""

import json
from http.client import HTTPConnection
from http.server import HTTPServer
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.manifest import create_manifest
from capgate.didhome.proof import ProofError, card_html, create_proof, verify_proof
from capgate.didhome.registry import Registry
from vouch.oidc import OIDCError, OIDCProvider, _make_handler, decode_jwt


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


def test_card_html_embeds_proof(world):
    registry, key = world
    proof = create_proof(registry.resolve("adam"), key, "this is my name")
    page = card_html(proof)
    assert "@adam" in page
    assert proof["signature"] in page


def test_proof_issued_at_is_int_for_browser_canonical_json(world):
    """web/verify.html re-canonicalises in JS; ints serialise identically."""
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


@pytest.fixture
def oidc_http_server(provider):
    server = HTTPServer(("127.0.0.1", 0), _make_handler(provider))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address
    server.shutdown()
    server.server_close()
    thread.join()


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


def test_authorize_http_rate_limit_is_not_double_consumed(
    world, oidc_http_server, provider
):
    provider.rate_limits["authorize"] = 1
    proof = _login_proof(world, provider)
    connection = HTTPConnection(*oidc_http_server)
    connection.request(
        "POST",
        "/authorize",
        json.dumps({"client_id": CLIENT, "redirect_uri": REDIRECT, "proof": proof}),
    )
    response = connection.getresponse()
    assert response.status == 200
    connection.close()
