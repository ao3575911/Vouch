// Checks docs/verify.html's verifier code against tests/vectors/canonical.json.
// Run: node tests/js/verify_vectors.mjs   (Node 22+, for WebCrypto Ed25519)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../../", import.meta.url);
const html = readFileSync(new URL("docs/verify.html", root), "utf8");
const match = html.match(/<script id="vouch-core">([\s\S]*?)<\/script>/);
assert.ok(match, "vouch-core script not found in docs/verify.html");
const { canonical, checkProof, checkPresentation } = new Function(
  match[1] + "\nreturn { canonical, checkProof, checkPresentation };")();
const vectors = JSON.parse(
  readFileSync(new URL("tests/vectors/canonical.json", root), "utf8"));

for (const c of vectors.canonical) {
  assert.equal(canonical(c.input), c.canonical, `canonical vector ${c.name}`);
}
assert.throws(() => canonical({ issued_at: 1.5 }), /non-integer/);

const { manifest, proof, forged_proof: forged } = vectors;
let r = await checkProof(proof, manifest);
assert.equal(r.level, "ok", r.text);
r = await checkProof(proof, manifest.root_public_key);
assert.equal(r.level, "ok", r.text);
r = await checkProof(proof, null);
assert.equal(r.level, "warn", r.text);
assert.match(r.text, /unpinned/);
r = await checkProof(forged, null);
assert.equal(r.level, "warn", r.text);
r = await checkProof(forged, manifest);
assert.equal(r.level, "bad", r.text);
r = await checkProof({ ...proof, statement: "Zoe, member" }, manifest);
assert.equal(r.level, "bad", r.text);
r = await checkProof({ ...proof, did: "did:home:eve" }, null);
assert.equal(r.level, "bad", r.text);

// Manifest self-signature: the pinned manifest has to verify on its own.
const { manifest_whole_ts: whole } = vectors;
r = await checkProof(proof, whole);
assert.equal(r.level, "ok", r.text);  // whole-number float timestamps
r = await checkProof(proof, { ...manifest, version: 2 });
assert.equal(r.level, "bad", r.text);
assert.match(r.text, /manifest signature invalid/);
r = await checkProof(forged, { ...manifest, root_public_key: forged.public_key });
assert.equal(r.level, "bad", r.text);  // swapped key, old signature
r = await checkProof(proof, { ...manifest, signature: "00" });
assert.equal(r.level, "bad", r.text);

// Presentations (vouches).
const pv = vectors.presentation;
const pres = pv.presentation;
const base = { audience: "shop.example", nonce: "4821", now: pv.now, revoked: [] };
r = await checkPresentation(pres, pv.manifests, base);
assert.equal(r.level, "ok", r.text);
assert.deepEqual(r.claims.map(c => c.value), [true, "Zo\u00eb Adams"]);
r = await checkPresentation(pres, pv.manifests, { ...base, min: 2 });
assert.equal(r.level, "bad", r.text);  // over18 has two vouchers, name only one
assert.equal(r.claims[0].ok, true);
r = await checkPresentation(pres, pv.manifests, { ...base, trust: ["pharmacy"] });
assert.equal(r.level, "bad", r.text);  // name is vouched only by @notary
r = await checkPresentation(pres, pv.manifests, { ...base, nonce: "9999" });
assert.match(r.text, /replay/);
r = await checkPresentation(pres, pv.manifests, { ...base, audience: "bar.example" });
assert.equal(r.level, "bad", r.text);
r = await checkPresentation(pres, pv.manifests, { ...base, now: pv.now + 400 });
assert.match(r.text, /old/);
r = await checkPresentation(pres, pv.manifests, { ...base, nonce: "" });
assert.equal(r.level, "warn", r.text);
r = await checkPresentation({ ...pres, show: ["over21"] }, pv.manifests, base);
assert.match(r.text, /holder signature invalid/);
const nameId = pres.attestations.find(a => a.claim === "name").id;
r = await checkPresentation(pres, pv.manifests, { ...base, revoked: [nameId] });
assert.equal(r.claims[1].ok, false);
assert.match(r.text, /revoked/);
r = await checkPresentation(pres, pv.manifests, { ...base, now: pres.attestations[1].expires_at + 1, maxAge: 1e9 });
assert.match(r.text, /expired/);
// A forged voucher manifest (holder's own key under @notary's name) fails.
const fakeNotary = { ...pv.manifests.notary, root_public_key: pv.manifests.adam.root_public_key };
r = await checkPresentation(pres, { ...pv.manifests, notary: fakeNotary }, base);
assert.equal(r.claims[1].ok, false);
const { notary, ...noNotary } = pv.manifests;
r = await checkPresentation(pres, noNotary, base);
assert.match(r.text, /no registry copy of @notary/);

console.log(`ok: ${vectors.canonical.length} canonical vectors, proof and presentation checks pass`);
