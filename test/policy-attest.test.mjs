// Contracts for the trust plane: the policy gate that confines analyzer queries
// and the digest attestation that guards generated-rule execution. These are the
// controls that keep an untrusted repo from steering the analyzers off-target, so
// their failure modes (path escape, oversize, tamper, unlisted) are asserted.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPolicy, policyDigest, assertQueryAllowed } from "../scripts/lib/policy.mjs";
import { digestBytes, assertRunnable } from "../scripts/lib/attest.mjs";
import { writePack, assertPackRunnable } from "../scripts/lib/rule-pack.mjs";

function tmpTarget() {
  const t = mkdtempSync(join(tmpdir(), "kz-pol-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}

test("policy: default is non-breaking (rawQuery allow) and override merges shallowly", () => {
  const t = tmpTarget();
  assert.equal(loadPolicy(t).effective.mcp.rawQuery, "allow");
  const d1 = policyDigest(t);
  writeFileSync(join(t, ".kuzushi", "policy.json"), JSON.stringify({ mcp: { rawQuery: "require-approval" } }));
  const eff = loadPolicy(t).effective;
  assert.equal(eff.mcp.rawQuery, "require-approval");
  assert.equal(eff.mcp.confineQueryPaths, true, "sibling mcp keys preserved by shallow merge");
  assert.notEqual(policyDigest(t), d1, "digest changes when policy changes");
});

test("query gate: always-on path confinement + size cap (independent of rawQuery)", () => {
  const t = tmpTarget();
  assert.equal(assertQueryAllowed({ queryPath: "/etc/passwd", fromPath: t }).blocked, "path");
  assert.equal(assertQueryAllowed({ inlineScript: "x".repeat(300000), fromPath: t }).blocked, "size");
  // a query inside the target tree is allowed
  mkdirSync(join(t, ".kuzushi", "runs", "x"), { recursive: true });
  const q = join(t, ".kuzushi", "runs", "x", "q.ql"); writeFileSync(q, "//");
  assert.equal(assertQueryAllowed({ queryPath: q, fromPath: t }).ok, true);
});

test("query gate: rawQuery lockdown gates raw vs pack queries", () => {
  const t = tmpTarget();
  writeFileSync(join(t, ".kuzushi", "policy.json"), JSON.stringify({ mcp: { rawQuery: "require-approval" } }));
  mkdirSync(join(t, ".kuzushi", "rules", "codeql"), { recursive: true });
  mkdirSync(join(t, ".kuzushi", "runs", "y"), { recursive: true });
  const packQ = join(t, ".kuzushi", "rules", "codeql", "r.ql"); writeFileSync(packQ, "//");
  const rawQ = join(t, ".kuzushi", "runs", "y", "q.ql"); writeFileSync(rawQ, "//");
  assert.equal(assertQueryAllowed({ queryPath: packQ, fromPath: t }).fromPack, true, "pack query runs under lockdown");
  const raw = assertQueryAllowed({ queryPath: rawQ, fromPath: t });
  assert.equal(raw.ok, false);
  assert.equal(raw.requiresApproval, true, "raw query needs approval under require-approval");
});

test("attestation: assertRunnable enforces compile-validated + matching digest", () => {
  const bytes = Buffer.from("rule body");
  const entry = { ruleId: "r1", digest: digestBytes(bytes), validated: { compile: true } };
  assert.ok(assertRunnable(entry, bytes));
  assert.throws(() => assertRunnable(entry, Buffer.from("tampered")), /digest mismatch/);
  assert.throws(() => assertRunnable({ ...entry, validated: { compile: false } }, bytes), /not marked validated/);
});

test("rule-pack: assertPackRunnable passes a listed+matching rule, refuses tamper + unlisted", () => {
  const t = tmpTarget();
  mkdirSync(join(t, ".kuzushi", "rules", "joern"), { recursive: true });
  const ruleFile = join(t, ".kuzushi", "rules", "joern", "k.sc");
  writeFileSync(ruleFile, "println(1)\n");
  writePack(t, [{ ruleId: "k", engine: "joern", file: ".kuzushi/rules/joern/k.sc", digest: digestBytes(Buffer.from("println(1)\n")), validated: { compile: true } }]);
  assert.ok(assertPackRunnable(t, ruleFile));
  writeFileSync(ruleFile, "println(2)\n"); // tamper
  assert.throws(() => assertPackRunnable(t, ruleFile), /digest mismatch/);
  const stray = join(t, ".kuzushi", "rules", "joern", "stray.sc"); writeFileSync(stray, "x");
  assert.throws(() => assertPackRunnable(t, stray), /not in the rule pack manifest/);
});
