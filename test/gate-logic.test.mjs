// Pure-logic contracts for the finalize gates — the validators that decide what
// gets promoted/accepted. The rule-synth gate in particular is where the v0.6.0
// seed-match regression lived, so its accept/reject paths are pinned here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gradeRule } from "../scripts/cmd/rule-synth-finalize.mjs";
import { finalizeChain } from "../scripts/cmd/chain-finalize.mjs";
import { finalizeMemExploitability } from "../scripts/cmd/mem-exploitability-finalize.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { storeFor, openRun } from "../scripts/lib/artifact-store.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-gate-")); }

// ---- rule-synth gate (compile → seed-match → repo-run → precision) ----------

test("gradeRule accepts a clean rule", () => {
  const g = gradeRule({ compile: { ok: true }, seedMatch: { ok: true, matched: true }, repoMatches: [{ file: "a", line: 1 }], repoFileCount: 100 });
  assert.equal(g.accepted, true);
  assert.equal(g.stages.seedMatch, "pass");
});

test("gradeRule rejects: no compile, no seed-match, over-count, over-density", () => {
  assert.match(gradeRule({ compile: { ok: false, stderr: "boom" }, repoMatches: [], repoFileCount: 9 }).rejectionReason, /^compile/);
  assert.match(gradeRule({ compile: { ok: true }, seedMatch: { ok: true, matched: false }, repoMatches: [], repoFileCount: 9 }).rejectionReason, /^seedMatch/);
  const many = Array.from({ length: 300 }, (_, i) => ({ file: `f${i}`, line: 1 }));
  assert.match(gradeRule({ compile: { ok: true }, seedMatch: { ok: true, matched: true }, repoMatches: many, repoFileCount: 1000 }).rejectionReason, /^precision/);
  const dense = [{ file: "a", line: 1 }, { file: "b", line: 1 }, { file: "c", line: 1 }];
  assert.match(gradeRule({ compile: { ok: true }, seedMatch: { ok: true, matched: true }, repoMatches: dense, repoFileCount: 4 }).rejectionReason, /^precision/);
});

// ---- chain-finalize validation ----------------------------------------------

function seedTwo(t) {
  upsertFindings(t, [
    { source: "threat-hunt", refId: "a", title: "authz bypass", severity: "high", cwe: "285", verdict: "exploitable", status: "open", evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x", nextChecks: [] },
    { source: "threat-hunt", refId: "b", title: "ssrf", severity: "medium", cwe: "918", verdict: "exploitable", status: "open", evidence: [{ filePath: "b.js", startLine: 2 }], rationale: "y", nextChecks: [] }
  ]);
  const d = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8"));
  return d.findings.map((f) => f.fingerprint);
}

test("chain: a valid 2-member chain tags members without changing status", () => {
  const t = tmp();
  const [fa, fb] = seedTwo(t);
  const run = openRun(t, "chain");
  writeFileSync(join(run.runDir, "draft.chain.json"), JSON.stringify({ chains: [{ title: "c", members: [fa, fb], severity: "critical", narrative: "x".repeat(130) }] }));
  const r = finalizeChain(t, run.runDir);
  assert.equal(r.chainCount, 1);
  const doc = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8"));
  const a = doc.findings.find((f) => f.fingerprint === fa);
  assert.ok(a.chains?.length, "member carries chain ref");
  assert.equal(a.status, "open", "status unchanged by chaining");
});

test("chain: rejects <2 members and unknown member (via subprocess exit code)", async () => {
  const t = tmp();
  const [fa] = seedTwo(t);
  const run = openRun(t, "chain");
  const { spawnSync } = await import("node:child_process");
  const finalize = new URL("../scripts/cmd/chain-finalize.mjs", import.meta.url).pathname;
  writeFileSync(join(run.runDir, "draft.chain.json"), JSON.stringify({ chains: [{ title: "c", members: [fa], severity: "high", narrative: "x".repeat(130) }] }));
  assert.notEqual(spawnSync("node", [finalize, "--target", t, "--run-dir", run.runDir], { encoding: "utf8" }).status, 0);
  writeFileSync(join(run.runDir, "draft.chain.json"), JSON.stringify({ chains: [{ title: "c", members: [fa, "deadbeef"], severity: "high", narrative: "x".repeat(130) }] }));
  assert.notEqual(spawnSync("node", [finalize, "--target", t, "--run-dir", run.runDir], { encoding: "utf8" }).status, 0);
});

// ---- mem-exploitability tier validation --------------------------------------

test("mem-exploitability: attaches a tier block; rejects an invalid tier", async () => {
  const t = tmp();
  upsertFindings(t, [{ source: "systems-hunt", refId: "m", title: "oob", severity: "high", cwe: "787", verdict: "exploitable", status: "open", evidence: [{ filePath: "p.c", startLine: 5 }], rationale: "x", nextChecks: [] }]);
  const fp = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0].fingerprint;
  const run = openRun(t, "mem-exploitability");
  const longR = "x".repeat(220);
  const good = { findingFingerprint: fp, tier: "dos", vulnShape: "overflow", controlOffset: "n/a", constraints: "len controllable", mitigationGaps: [], rationale: longR, remediation: "bound the copy and enable canary", evidenceAnchors: [{ filePath: "p.c", startLine: 5 }] };
  writeFileSync(join(run.runDir, "draft.mem-exploitability.json"), JSON.stringify({ candidates: [good] }));
  const r = finalizeMemExploitability(t, run.runDir);
  assert.equal(r.tierCounts.dos, 1);
  const f = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings[0];
  assert.equal(f.exploitability.tier, "dos");
  assert.equal(f.status, "open", "assessment does not change status");

  const { spawnSync } = await import("node:child_process");
  const finalize = new URL("../scripts/cmd/mem-exploitability-finalize.mjs", import.meta.url).pathname;
  writeFileSync(join(run.runDir, "draft.mem-exploitability.json"), JSON.stringify({ candidates: [{ ...good, tier: "pwned" }] }));
  assert.notEqual(spawnSync("node", [finalize, "--target", t, "--run-dir", run.runDir], { encoding: "utf8" }).status, 0, "invalid tier rejected");
});
