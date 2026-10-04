"""did:home CLI — handle's UX on capgate's crypto. Zero hosting cost.

    claim @adam --registry ./registry
    whoami @adam
    delegate @adam calendar ping:send email:draft
    revoke @adam <token_id>
    ping @adam @sam --token t.json --body '{"msg":"hi"}'
    verify-ping ping.json
    move @adam --out bundle.json
    verify-registry ./registry

Keys live in a local keystore (default ``~/.didhome``), never in the
registry. The registry directory is intended to be a public git repo.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from capgate.didhome.delegation import CapabilityToken, issue_capability_token
from capgate.didhome.manifest import create_manifest, update_manifest, validate_handle
from capgate.didhome.ping import Ping, create_ping, verify_ping
from capgate.didhome.proof import card_html, create_proof
from capgate.didhome.recovery import approve_recovery
from capgate.didhome.registry import Registry, export_bundle


def _key_to_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _key_from_hex(hex_key: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))


class Keystore:
    """Local private-key store: one hex key file per identity name."""

    def __init__(self, home: str | Path):
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        return self.home / f"{name}.key"

    def save(self, name: str, key: Ed25519PrivateKey) -> None:
        path = self._path(name)
        path.write_text(_key_to_hex(key), encoding="utf-8")
        os.chmod(path, 0o600)

    def load(self, name: str) -> Ed25519PrivateKey:
        path = self._path(name)
        if not path.exists():
            raise SystemExit(f"error: no key for {name!r} in {self.home}")
        return _key_from_hex(path.read_text(encoding="utf-8").strip())


def _parse_services(items: list[str]) -> list[dict[str, str]]:
    services = []
    for item in items:
        try:
            sid, stype, endpoint = item.split("=", 2)
        except ValueError:
            raise SystemExit(f"error: bad --service {item!r}; want id=type=endpoint") from None
        services.append({"id": sid, "type": stype, "endpoint": endpoint})
    return services


def cmd_claim(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = Keystore(args.home)
    key = Ed25519PrivateKey.generate()
    manifest = create_manifest(name, key, services=_parse_services(args.service))
    Registry(args.registry).claim(manifest, key)
    ks.save(name, key)
    print(f"claimed @{name} -> {manifest.did}")
    print(f"manifest: {Path(args.registry) / 'names' / (name + '.json')}")
    print(f"key:      {ks._path(name)}")


def cmd_whoami(args: argparse.Namespace) -> None:
    manifest = Registry(args.registry).resolve(args.handle)
    print(json.dumps(manifest.to_dict(), sort_keys=True, indent=2))


def cmd_delegate(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = Keystore(args.home)
    root_key = ks.load(name)
    registry = Registry(args.registry)
    manifest = registry.resolve(name)
    subject = f"{args.subject}@{name}"
    subject_key = Ed25519PrivateKey.generate()
    token = issue_capability_token(
        manifest.did, root_key, subject, subject_key, args.permissions
    )
    agents = [a for a in manifest.agents if a["id"] != subject]
    agents.append(
        {"id": subject, "public_key": token.subject_public_key, "token_id": token.token_id}
    )
    registry.update(update_manifest(manifest, root_key, agents=agents), root_key)
    ks.save(subject, subject_key)
    out = Path(args.out) if args.out else Path(f"{args.subject}.{name}.token.json")
    out.write_text(json.dumps(token.to_dict(), sort_keys=True, indent=2), encoding="utf-8")
    print(f"delegated {subject} with {sorted(token.permissions)}")
    print(f"token:    {out}")


def cmd_revoke(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    root_key = Keystore(args.home).load(name)
    Registry(args.registry).revoke_token(name, args.token_id, root_key)
    print(f"revoked token {args.token_id} for @{name}")


def cmd_ping(args: argparse.Namespace) -> None:
    sender = validate_handle(args.sender)
    token = CapabilityToken.from_dict(json.loads(Path(args.token).read_text(encoding="utf-8")))
    subject_key = Keystore(args.home).load(token.subject)
    ping = create_ping(
        f"did:home:{sender}",
        f"did:home:{validate_handle(args.recipient)}",
        json.loads(args.body),
        token,
        subject_key,
    )
    out = Path(args.out) if args.out else Path("ping.json")
    out.write_text(json.dumps(ping.to_dict(), sort_keys=True, indent=2), encoding="utf-8")
    print(f"ping {args.sender} -> {args.recipient}: {out}")


def cmd_verify_ping(args: argparse.Namespace) -> None:
    data = json.loads(Path(args.ping).read_text(encoding="utf-8"))
    ping = Ping(**data)
    verify_ping(Registry(args.registry), ping, set())
    print(f"ping verified: {ping.sender} -> {ping.recipient}")


def cmd_move(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = Keystore(args.home)
    bundle = export_bundle(Registry(args.registry), name, _key_to_hex(ks.load(name)))
    out = Path(args.out)
    out.write_text(json.dumps(bundle, sort_keys=True, indent=2), encoding="utf-8")
    os.chmod(out, 0o600)
    print(f"exported portable identity bundle for @{name}: {out}")
    print("warning: bundle contains the private key — keep it secret")


def cmd_verify_registry(args: argparse.Namespace) -> None:
    registry = Registry(args.registry)
    count = registry.verify()
    print(f"registry OK: {len(registry.handles())} handles, {count} events, chain verified")


def cmd_card(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    root_key = Keystore(args.home).load(name)
    manifest = Registry(args.registry).resolve(name)
    proof = create_proof(manifest, root_key, args.statement)
    if args.json:
        print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
        return
    out = Path(args.out) if args.out else Path(f"{name}.card.html")
    out.write_text(card_html(proof), encoding="utf-8")
    print(f"printable card for @{name}: {out}")
    print("verify it offline with web/verify.html")


def cmd_set_guardians(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    root_key = Keystore(args.home).load(name)
    guardians = [validate_handle(g) for g in args.guardians]
    Registry(args.registry).set_guardians(name, guardians, args.threshold, root_key)
    print(f"guardians for @{name}: {sorted(guardians)} (threshold {args.threshold})")


def cmd_recover_start(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = Keystore(args.home)
    key = Ed25519PrivateKey.generate()
    ks.save(f"{name}.recovering", key)
    from capgate.didhome.manifest import public_key_hex

    print(f"new public key for @{name}: {public_key_hex(key.public_key())}")
    print("ask your guardians to run: approve-recovery <guardian> " + f"@{name}")


def cmd_approve_recovery(args: argparse.Namespace) -> None:
    guardian = validate_handle(args.guardian)
    guardian_key = Keystore(args.home).load(guardian)
    registry = Registry(args.registry)
    prior = registry.resolve(args.handle).root_public_key
    approval = approve_recovery(
        guardian, guardian_key, args.handle, args.new_public_key, prior
    )
    out = Path(args.out) if args.out else Path(f"{guardian}.approval.json")
    out.write_text(json.dumps(approval, sort_keys=True, indent=2), encoding="utf-8")
    print(f"approval by @{guardian} for @{validate_handle(args.handle)}: {out}")


def cmd_recover(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = Keystore(args.home)
    new_key = ks.load(f"{name}.recovering")
    approvals = [
        json.loads(Path(p).read_text(encoding="utf-8")) for p in args.approvals
    ]
    Registry(args.registry).recover(name, new_key, approvals)
    ks.save(name, new_key)
    print(f"recovered @{name}: root key rotated, manifest re-signed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="didhome", description=__doc__)
    parser.add_argument("--home", default=os.path.expanduser("~/.didhome"), help="keystore dir")
    parser.add_argument("--registry", default="./registry", help="registry dir")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("claim", help="claim a handle: keypair + signed manifest + registry entry")
    p.add_argument("handle")
    p.add_argument("--service", action="append", default=[], help="id=type=endpoint")
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("whoami", help="resolve and print a handle's manifest")
    p.add_argument("handle")
    p.set_defaults(func=cmd_whoami)

    p = sub.add_parser("delegate", help="mint a scoped sub-identity + capability token")
    p.add_argument("handle")
    p.add_argument("subject", help="sub-identity name, e.g. calendar")
    p.add_argument("permissions", nargs="+")
    p.add_argument("--out")
    p.set_defaults(func=cmd_delegate)

    p = sub.add_parser("revoke", help="revoke a capability token")
    p.add_argument("handle")
    p.add_argument("token_id")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("ping", help="create a signed agent-to-agent ping")
    p.add_argument("sender")
    p.add_argument("recipient")
    p.add_argument("--token", required=True)
    p.add_argument("--body", default="{}")
    p.add_argument("--out")
    p.set_defaults(func=cmd_ping)

    p = sub.add_parser("verify-ping", help="verify a signed ping against the registry")
    p.add_argument("ping")
    p.set_defaults(func=cmd_verify_ping)

    p = sub.add_parser("move", help="export a portable identity bundle")
    p.add_argument("handle")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_move)

    p = sub.add_parser("verify-registry", help="offline-verify the whole registry (CI gate)")
    p.set_defaults(func=cmd_verify_registry)

    p = sub.add_parser("card", help="emit a printable proof card (verify with web/verify.html)")
    p.add_argument("handle")
    p.add_argument("--statement", default="this is my name", help="what the card proves")
    p.add_argument("--out", help="output HTML file")
    p.add_argument("--json", action="store_true", help="print proof JSON instead of HTML")
    p.set_defaults(func=cmd_card)

    p = sub.add_parser("set-guardians", help="declare N-of-M recovery guardians")
    p.add_argument("handle")
    p.add_argument("guardians", nargs="+", help="guardian handles")
    p.add_argument("--threshold", type=int, required=True)
    p.set_defaults(func=cmd_set_guardians)

    p = sub.add_parser("recover-start", help="generate a new key and print its public half")
    p.add_argument("handle")
    p.set_defaults(func=cmd_recover_start)

    p = sub.add_parser("approve-recovery", help="guardian signs off on a key rotation")
    p.add_argument("guardian")
    p.add_argument("handle")
    p.add_argument("--new-public-key", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_approve_recovery)

    p = sub.add_parser("recover", help="rotate the root key with guardian approvals")
    p.add_argument("handle")
    p.add_argument("--approval", dest="approvals", action="append", required=True)
    p.set_defaults(func=cmd_recover)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
