"""did:home — a free, local-first DID namespace for agents.

The handle is the product: ``@adam`` binds to ``did:home:adam``, whose DID
document is a self-signed Ed25519 manifest. Resolution is a static file
registry (a public git repo / Pages site), tamper-evident via a
hash-chained, signed event log. Utility is capability-scoped delegation:
``calendar@adam`` acts for ``@adam`` with exactly the permissions the root
key granted — verifiable by anyone with the registry. No VM, no mail
gateway, no storage service, no billing.

See docs/did-home-spec.md for the method specification.
"""

from capgate.didhome.delegation import (
    CapabilityToken,
    DelegationError,
    issue_capability_token,
    verify_capability_token,
)
from capgate.didhome.manifest import (
    Manifest,
    ManifestError,
    create_manifest,
    did_for_handle,
    update_manifest,
    validate_handle,
    verify_manifest,
)
from capgate.didhome.ping import Ping, PingError, create_ping, verify_ping
from capgate.didhome.proof import ProofError, card_html, create_proof, verify_proof
from capgate.didhome.recovery import (
    RecoveryError,
    approve_recovery,
    issue_child_identity,
    verify_approvals,
)
from capgate.didhome.registry import Registry, RegistryError, export_bundle

__all__ = [
    "CapabilityToken",
    "DelegationError",
    "Manifest",
    "ManifestError",
    "Ping",
    "PingError",
    "ProofError",
    "RecoveryError",
    "Registry",
    "RegistryError",
    "approve_recovery",
    "card_html",
    "create_manifest",
    "create_ping",
    "create_proof",
    "did_for_handle",
    "export_bundle",
    "issue_capability_token",
    "issue_child_identity",
    "update_manifest",
    "validate_handle",
    "verify_approvals",
    "verify_capability_token",
    "verify_manifest",
    "verify_ping",
    "verify_proof",
]
