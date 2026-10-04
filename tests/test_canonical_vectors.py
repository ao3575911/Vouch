"""Shared canonical-JSON vectors, also checked in JS by tests/js/verify_vectors.mjs."""

import json
from pathlib import Path

import pytest

from capgate.didhome.manifest import Manifest, _canonical_json, verify_manifest
from capgate.didhome.proof import ProofError, verify_proof

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "canonical.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", VECTORS["canonical"], ids=lambda c: c["name"])
def test_canonical_vector(case):
    assert _canonical_json(case["input"]).decode("ascii") == case["canonical"]


def test_non_ascii_proof_vector_verifies_pinned():
    manifest = Manifest.from_dict(VECTORS["manifest"])
    verify_manifest(manifest)
    proof = VECTORS["proof"]
    assert proof["statement"] == "Zo\u00eb, member"
    verify_proof(proof, expected_public_key=manifest.root_public_key)


def test_forged_proof_vector_fails_pinned():
    manifest = Manifest.from_dict(VECTORS["manifest"])
    forged = VECTORS["forged_proof"]
    verify_proof(forged)  # self-consistent, but not adam's registry key
    with pytest.raises(ProofError, match="unexpected key"):
        verify_proof(forged, expected_public_key=manifest.root_public_key)
