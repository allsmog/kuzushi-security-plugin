// Engine-gated end-to-end: when joern (or codeql) is actually installed, prove
// /rule-synth's gate runs for real — compile → fire-on-seed → repo-run →
// precision → attested pack → promote. Skips cleanly on machines without the
// engine so `npm test` stays green everywhere, but pins the real path in CI
// where the engine exists (this is the surface where v0.6.0 shipped broken).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { prepareRuleSynth } from "../scripts/cmd/rule-synth-prepare.mjs";
import { finalizeRuleSynth } from "../scripts/cmd/rule-synth-finalize.mjs";
import { joern } from "../scripts/lib/rule-engines.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

function joernInstalled() {
  const r = spawnSync("joern", ["--version"], { encoding: "utf8", timeout: 10000 });
  return !r.error && (r.status === 0 || r.status === null);
}

test("rule-synth end-to-end against a real Joern CPG", { skip: joernInstalled() ? false : "joern not installed" }, () => {
  const t = mkdtempSync(join(tmpdir(), "kz-rsj-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src", "a.c"), '#include <stdlib.h>\n#include <string.h>\nint run(char *u){char c[256];strcpy(c,u);return system(c);}\n');
  writeFileSync(join(t, "src", "b.c"), '#include <stdlib.h>\nint m(char *a){return system(a);}\n');
  mkdirSync(join(t, ".kuzushi", "joern"), { recursive: true });
  const cpg = join(t, ".kuzushi", "joern", "cpg.bin.zip");
  const parse = spawnSync("joern-parse", [join(t, "src"), "--output", cpg], { encoding: "utf8", timeout: 180000, cwd: tmpdir() });
  assert.ok(existsSync(cpg), `joern-parse produced a CPG (${(parse.stderr || "").slice(-200)})`);

  // Seed the system() call in a.c (line 3) as a confirmed finding.
  upsertFindings(t, [{ source: "verify", refId: "cmdi", title: "system() injection", severity: "high", cwe: "78", verdict: "confirmed-exploitable", status: "confirmed", evidence: [{ filePath: "src/a.c", startLine: 3 }], rationale: "user→system", nextChecks: [] }]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;

  assert.equal(joern.available(t).available, true, "joern engine available with the built CPG");
  const prep = prepareRuleSynth(t, {});
  assert.equal(prep.status, "prepared");

  // A real Joern rule for the system() sink, reading the CPG from KUZUSHI_CPG.
  const ruleFile = join(prep.runDir, `rule.${fp}.sc`);
  writeFileSync(ruleFile, [
    'importCpg(sys.env("KUZUSHI_CPG"))',
    'cpg.call.name("system").foreach{c=>println(s"KUZUSHI_MATCH\\t${c.file.name.headOption.getOrElse("")}\\t${c.lineNumber.getOrElse(0)}")}'
  ].join("\n"));
  writeFileSync(prep.draftPath, JSON.stringify({ rules: [{ ruleId: `kuzushi.rulesynth.${fp}`, engine: "joern", seedRef: fp, language: "c", cwe: "78", severity: "high", title: "system sink", ruleFile: `rule.${fp}.sc` }] }));

  const r = finalizeRuleSynth(t, prep.runDir);
  assert.equal(r.summary.accepted, 1, "rule passed compile→seed-match→repo-run→precision");
  const rec = JSON.parse(readFileSync(storeFor(t).ruleSynthPath, "utf8")).rules[0];
  assert.equal(rec.seedMatch, "pass", "fired on the seed line (the v0.6.0 regression)");
  const pack = JSON.parse(readFileSync(storeFor(t).rulePackManifestPath, "utf8"));
  assert.ok(pack.rules[0]?.digest, "accepted rule persisted to the attested pack with a digest");
  const promoted = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings.filter((f) => f.source === "rule-synth");
  assert.ok(promoted.length >= 1, "sibling matches promoted as candidate leads");
});
