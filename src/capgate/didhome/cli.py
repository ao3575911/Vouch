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
import getpass
import json
import os
import secrets
import sys
import time
from datetime import date, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from capgate.didhome.attest import (
    AttestationError,
    create_attestation,
    create_presentation,
    derive_age_claims,
    over_claim,
    verify_attestation,
    verify_presentation,
)
from capgate.didhome.delegation import CapabilityToken, issue_capability_token
from capgate.didhome.manifest import (
    HANDLE_RE,
    create_manifest,
    update_manifest,
    validate_handle,
)
from capgate.didhome.ping import Ping, create_ping, verify_ping
from capgate.didhome.proof import VERIFY_URL, card_html, create_proof
from capgate.didhome.recovery import approve_recovery
from capgate.didhome.registry import Registry, export_bundle

PASSPHRASE_ENV = "VOUCH_ID_PASSPHRASE"
_ENCRYPTED_PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----"


def _key_to_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _key_from_hex(hex_key: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))


def encode_key(key: Ed25519PrivateKey, passphrase: str | None) -> str:
    """Raw hex without a passphrase, encrypted PKCS#8 PEM with one."""
    if not passphrase:
        return _key_to_hex(key)
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(passphrase.encode())
    ).decode("ascii")


def decode_key(text: str, passphrase: str | None) -> Ed25519PrivateKey:
    text = text.strip()
    if not text.startswith(_ENCRYPTED_PEM):
        return _key_from_hex(text)
    if not passphrase:
        raise SystemExit(f"error: key is encrypted; set {PASSPHRASE_ENV} or pass --passphrase")
    try:
        key = load_pem_private_key(text.encode("ascii"), passphrase.encode())
    except ValueError:
        raise SystemExit("error: wrong passphrase") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("error: not an Ed25519 key")
    return key


def write_secret(path: Path, text: str) -> None:
    """Write a file that is 0600 from the moment it exists, then move it into place."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class Keystore:
    """Local private-key store: one key file per identity name.

    Without a passphrase a key file holds raw hex. With one it holds an
    encrypted PKCS#8 PEM (cryptography's BestAvailableEncryption).
    """

    def __init__(self, home: str | Path, passphrase: str | None = None):
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.passphrase = passphrase

    def _path(self, name: str) -> Path:
        return self.home / f"{name}.key"

    def save(self, name: str, key: Ed25519PrivateKey) -> None:
        write_secret(self._path(name), encode_key(key, self.passphrase))

    def load(self, name: str) -> Ed25519PrivateKey:
        path = self._path(name)
        if not path.exists():
            raise SystemExit(f"error: no key for {name!r} in {self.home}")
        return decode_key(path.read_text(encoding="utf-8"), self.passphrase)


def _passphrase(args: argparse.Namespace) -> str | None:
    if getattr(args, "passphrase", False):
        return getpass.getpass("passphrase: ")
    return os.environ.get(PASSPHRASE_ENV) or None


def _keystore(args: argparse.Namespace) -> Keystore:
    return Keystore(args.home, _passphrase(args))


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
    ks = _keystore(args)
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
    ks = _keystore(args)
    root_key = ks.load(name)
    registry = Registry(args.registry)
    manifest = registry.resolve(name)
    subject = f"{args.subject}@{name}"
    subject_key = Ed25519PrivateKey.generate()
    token = issue_capability_token(manifest.did, root_key, subject, subject_key, args.permissions)
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
    root_key = _keystore(args).load(name)
    Registry(args.registry).revoke_token(name, args.token_id, root_key)
    print(f"revoked token {args.token_id} for @{name}")


def cmd_ping(args: argparse.Namespace) -> None:
    sender = validate_handle(args.sender)
    token = CapabilityToken.from_dict(json.loads(Path(args.token).read_text(encoding="utf-8")))
    subject_key = _keystore(args).load(token.subject)
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
    ks = _keystore(args)
    key_text = None if args.without_key else encode_key(ks.load(name), ks.passphrase)
    bundle = export_bundle(Registry(args.registry), name, key_text)
    out = Path(args.out)
    write_secret(out, json.dumps(bundle, sort_keys=True, indent=2))
    print(f"exported portable identity bundle for @{name}: {out}")
    if key_text is None:
        print("bundle has no private key")
    elif ks.passphrase:
        print("bundle contains the private key, encrypted with your passphrase")
    else:
        print("warning: bundle contains the private key — keep it secret")


def cmd_verify_registry(args: argparse.Namespace) -> None:
    registry = Registry(args.registry)
    count = registry.verify()
    print(f"registry OK: {len(registry.handles())} handles, {count} events, chain verified")


def cmd_card(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    root_key = _keystore(args).load(name)
    manifest = Registry(args.registry).resolve(name)
    proof = create_proof(manifest, root_key, args.statement)
    if args.json:
        print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
        return
    out = Path(args.out) if args.out else Path(f"{name}.card.html")
    out.write_text(card_html(proof), encoding="utf-8")
    print(f"printable card for @{name}: {out}")
    print(f"verify it at {VERIFY_URL} (works offline once loaded)")


def cmd_set_guardians(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    root_key = _keystore(args).load(name)
    guardians = [validate_handle(g) for g in args.guardians]
    Registry(args.registry).set_guardians(name, guardians, args.threshold, root_key)
    print(f"guardians for @{name}: {sorted(guardians)} (threshold {args.threshold})")


def cmd_recover_start(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = _keystore(args)
    key = Ed25519PrivateKey.generate()
    ks.save(f"{name}.recovering", key)
    from capgate.didhome.manifest import public_key_hex

    print(f"new public key for @{name}: {public_key_hex(key.public_key())}")
    print("ask your guardians to run: approve-recovery <guardian> " + f"@{name}")


def cmd_approve_recovery(args: argparse.Namespace) -> None:
    guardian = validate_handle(args.guardian)
    guardian_key = _keystore(args).load(guardian)
    registry = Registry(args.registry)
    prior = registry.resolve(args.handle).root_public_key
    approval = approve_recovery(guardian, guardian_key, args.handle, args.new_public_key, prior)
    out = Path(args.out) if args.out else Path(f"{guardian}.approval.json")
    out.write_text(json.dumps(approval, sort_keys=True, indent=2), encoding="utf-8")
    print(f"approval by @{guardian} for @{validate_handle(args.handle)}: {out}")


def cmd_recover(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    ks = _keystore(args)
    new_key = ks.load(f"{name}.recovering")
    approvals = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.approvals]
    Registry(args.registry).recover(name, new_key, approvals)
    ks.save(name, new_key)
    print(f"recovered @{name}: root key rotated, manifest re-signed")


def _signer(ks: Keystore, as_handle: str | None) -> str:
    """The handle to sign with: --as, or the only root key in the keystore."""
    if as_handle:
        return validate_handle(as_handle)
    names = sorted(p.stem for p in ks.home.glob("*.key") if HANDLE_RE.match(p.stem))
    if len(names) != 1:
        raise SystemExit("error: say who is vouching with --as @handle")
    return names[0]


def _parse_expiry(text: str | None, now: float) -> int | None:
    if not text:
        return None
    units = {"d": 86400, "y": 365 * 86400}
    if text[:-1].isdigit() and text[-1] in units:
        return int(now) + int(text[:-1]) * units[text[-1]]
    try:
        return int(datetime.fromisoformat(text).astimezone().timestamp())
    except ValueError:
        raise SystemExit(f"error: bad --expires {text!r}; want 365d, 5y or YYYY-MM-DD") from None


def cmd_attest(args: argparse.Namespace) -> None:
    ks = _keystore(args)
    voucher = _signer(ks, args.as_handle)
    key = ks.load(voucher)
    registry = Registry(args.registry)
    voucher_manifest = registry.resolve(voucher)
    subject = registry.resolve(args.subject)
    claims: list[tuple[str, object]] = [(over_claim(n), True) for n in args.over]
    if args.birthdate:
        # Used here to work out the age thresholds, then dropped.
        derived = derive_age_claims(date.fromisoformat(args.birthdate))
        if not derived:
            raise SystemExit("error: that birthdate is under every age threshold")
        claims += [(c, True) for c in derived]
    if args.name:
        claims.append(("name", args.name))
    for item in args.claim:
        name, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"error: bad --claim {item!r}; want key=value")
        claims.append((name, value))
    if not claims:
        raise SystemExit("error: nothing to vouch for; use --over, --name or --claim")
    now = time.time()
    expires = _parse_expiry(args.expires, now)
    atts = [
        create_attestation(voucher_manifest, key, subject, c, v, args.method, expires, now)
        for c, v in dict(claims).items()
    ]
    out = Path(args.out) if args.out else Path(f"{subject.handle}.vouch.json")
    out.write_text(json.dumps(atts, sort_keys=True, indent=2), encoding="utf-8")
    shown = ", ".join(a["claim"] for a in atts)
    print(f"@{voucher} vouched for @{subject.handle}: {shown} ({args.method})")
    print(f"give {out} to @{subject.handle}; they add it with: keep @{subject.handle} {out}")


def _vouch_dir(home: str, handle: str) -> Path:
    return Path(home) / "vouches" / validate_handle(handle)


def _load_atts(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def cmd_keep(args: argparse.Namespace) -> None:
    registry = Registry(args.registry)
    did = registry.resolve(args.handle).did
    folder = _vouch_dir(args.home, args.handle)
    folder.mkdir(parents=True, exist_ok=True)
    for att in _load_atts(Path(args.file)):
        if att.get("subject") != did:
            raise SystemExit(f"error: vouch {att.get('id')} is not about @{args.handle}")
        verify_attestation(registry, att)
        (folder / f"{att['id']}.json").write_text(
            json.dumps(att, sort_keys=True, indent=2), encoding="utf-8"
        )
        print(f"kept: {att['claim']} from {att['voucher'].removeprefix('did:home:')}")


def cmd_present(args: argparse.Namespace) -> None:
    name = validate_handle(args.handle)
    key = _keystore(args).load(name)
    manifest = Registry(args.registry).resolve(name)
    atts: list[dict] = []
    for path in sorted(_vouch_dir(args.home, name).glob("*.json")):
        atts += _load_atts(path)
    for path in args.vouch:
        atts += _load_atts(Path(path))
    show = [s.strip() for item in args.show for s in item.split(",") if s.strip()]
    pres = create_presentation(manifest, key, atts, show, audience=args.audience, nonce=args.nonce)
    text = json.dumps(pres, sort_keys=True, separators=(",", ":"))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"presentation for {', '.join(show)}: {args.out} (valid for 5 minutes)")
    else:
        print(text)


def cmd_revoke_attestation(args: argparse.Namespace) -> None:
    ks = _keystore(args)
    voucher = _signer(ks, args.as_handle)
    Registry(args.registry).revoke_attestation(voucher, args.attestation_id, ks.load(voucher))
    print(f"@{voucher} withdrew vouch {args.attestation_id}")


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d")


def cmd_verify_presentation(args: argparse.Namespace) -> None:
    pres = json.loads(Path(args.file).read_text(encoding="utf-8"))
    trust = None
    if args.trust:
        trust = {validate_handle(h.strip()) for h in args.trust.split(",") if h.strip()}
    try:
        result = verify_presentation(
            Registry(args.registry),
            pres,
            audience=args.audience,
            nonce=args.nonce,
            trust=trust,
            min_vouchers=args.min,
        )
    except AttestationError as exc:
        print(f"NOT VERIFIED: {exc}")
        raise SystemExit(1) from None
    print(f"presentation from {result.holder}, signed by their current key")
    if not result.bound:
        print("warning: no --nonce given, so this could be a replayed presentation")
    for c in result.claims:
        value = "yes" if c.value is True else (repr(c.value) if c.value is not None else "-")
        status = "OK" if c.ok else "NOT ENOUGH"
        print(f"{c.wanted}: {value}  [{status}: {len(c.vouchers)} of {args.min} needed]")
        for v in c.vouchers:
            until = f", until {_when(v['expires_at'])}" if v["expires_at"] else ""
            print(f"  vouched by {v['voucher']} ({v['method']}, {_when(v['issued_at'])}{until})")
    for label, reason in result.rejected:
        print(f"  ignored {label}: {reason}")
    if not result.ok:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="didhome", description=__doc__)
    parser.add_argument("--home", default=os.path.expanduser("~/.didhome"), help="keystore dir")
    parser.add_argument("--registry", default="./registry", help="registry dir")
    parser.add_argument(
        "--passphrase",
        action="store_true",
        help=f"prompt for a passphrase to encrypt or unlock keys (or set {PASSPHRASE_ENV})",
    )
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
    p.add_argument("--without-key", action="store_true", help="leave the private key out")
    p.set_defaults(func=cmd_move)

    p = sub.add_parser("verify-registry", help="offline-verify the whole registry (CI gate)")
    p.set_defaults(func=cmd_verify_registry)

    p = sub.add_parser("card", help=f"emit a printable proof card (verify at {VERIFY_URL})")
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

    p = sub.add_parser("attest", help="vouch for someone: sign a claim about their handle")
    p.add_argument("subject", help="who you are vouching for, e.g. @adam")
    p.add_argument("--as", dest="as_handle", help="your handle (if you hold more than one)")
    p.add_argument("--over", type=int, action="append", default=[], metavar="AGE")
    p.add_argument("--birthdate", help="YYYY-MM-DD; used to work out --over claims, never stored")
    p.add_argument("--name", help="their full name")
    p.add_argument("--claim", action="append", default=[], metavar="KEY=VALUE")
    p.add_argument(
        "--method",
        required=True,
        help="how you checked, e.g. saw-passport, in-person, known-5-years",
    )
    p.add_argument("--expires", help="365d, 5y or YYYY-MM-DD (default: no expiry)")
    p.add_argument("--out")
    p.set_defaults(func=cmd_attest)

    p = sub.add_parser("keep", help="check vouches someone gave you and store them")
    p.add_argument("handle")
    p.add_argument("file")
    p.set_defaults(func=cmd_keep)

    p = sub.add_parser("present", help="show vouched claims to a verifier")
    p.add_argument("handle")
    p.add_argument("--show", action="append", required=True, help="e.g. over18 or name")
    p.add_argument("--audience", default="", help="who it is for, e.g. shop.example")
    p.add_argument("--nonce", default="", help="the code the verifier gave you")
    p.add_argument("--vouch", action="append", default=[], help="extra vouch file")
    p.add_argument("--out")
    p.set_defaults(func=cmd_present)

    p = sub.add_parser("revoke-attestation", help="withdraw a vouch you made")
    p.add_argument("attestation_id")
    p.add_argument("--as", dest="as_handle")
    p.set_defaults(func=cmd_revoke_attestation)

    p = sub.add_parser("verify-presentation", help="check a presentation against the registry")
    p.add_argument("file")
    p.add_argument("--audience", help="require this audience")
    p.add_argument("--nonce", help="require the nonce you gave the holder")
    p.add_argument("--trust", help="only count these vouchers, e.g. @pharmacy,@notary")
    p.add_argument("--min", type=int, default=1, help="vouchers needed per claim (default 1)")
    p.set_defaults(func=cmd_verify_presentation)

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
