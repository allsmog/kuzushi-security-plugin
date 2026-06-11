// The shipped starter pack closes the "no default queries, agent writes raw
// CodeQL/Joern on every run" gap. These pin that install copies the curated
// queries in, registers them in the digest-attested manifest, and that the
// execution gate (assertPackRunnable) then ACCEPTS them — and rejects tampering.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { installStarterPack } from "../scripts/cmd/install-starter-pack.mjs";
import { assertPackRunnable, loadPack } from "../scripts/lib/rule-pack.mjs";
import { assertValid } from "../scripts/lib/schemas.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-starter-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}

test("install copies the starter queries and writes a valid, digest-attested pack", () => {
  const t = repo();
  const res = installStarterPack(t);
  assert.equal(res.status, "completed");
  assert.ok(res.installedCount >= 23, "ships the deepened curated rule set");
  const pack = loadPack(t);
  assertValid("rulePack", pack); // manifest is schema-valid (ruleId/engine/file/digest/validated)
  // The actual query files landed under .kuzushi/rules/.
  for (const rel of res.installed) assert.ok(existsSync(join(t, rel)), `installed ${rel}`);
});

test("the execution gate accepts an installed query, and rejects it once tampered", () => {
  const t = repo();
  installStarterPack(t);
  const codeqlRule = loadPack(t).rules.find((r) => r.engine === "codeql");
  const rulePath = join(t, codeqlRule.file);
  // Pristine install → runnable.
  assert.doesNotThrow(() => assertPackRunnable(t, rulePath));
  // Tamper the bytes → digest mismatch → the gate refuses to execute.
  writeFileSync(rulePath, readFileSync(rulePath, "utf8") + "\n// injected\n");
  assert.throws(() => assertPackRunnable(t, rulePath), /digest mismatch/);
});
