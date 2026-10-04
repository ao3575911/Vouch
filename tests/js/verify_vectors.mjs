// Checks docs/verify.html's verifier code against tests/vectors/canonical.json.
// Run: node tests/js/verify_vectors.mjs   (Node 22+, for WebCrypto Ed25519)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../../", import.meta.url);
const html = readFileSync(new URL("docs/verify.html", root), "utf8");
const match = html.match(/<script id="vouch-core">([\s\S]*?)<\/script>/);
assert.ok(match, "vouch-core script not found in docs/verify.html");
const { canonical, checkProof } = new Function(
  match[1] + "\nreturn { canonical, checkProof };")();
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

console.log(`ok: ${vectors.canonical.length} canonical vectors, proof checks pass`);
