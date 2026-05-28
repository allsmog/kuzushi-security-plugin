// Contracts for /deep-scan — the whole-file deep reader. The prepare must produce a
// risk-RANKED file list (security-relevant / entry-point files first) with an honest
// unreadCount, and the finalize must promote read-derived hypotheses while gating
// bad verdicts and finding-without-CWE. This is the producer that removes the
// pattern-gating recall ceiling, so its determinism (ranking + validation) matters.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { rankFiles } from "../scripts/lib/risk-rank.mjs";
import { prepareDeepScan } from "../scripts/cmd/deep-scan-prepare.mjs";
import { finalizeDeepScan } from "../scripts/cmd/deep-scan-finalize.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-deep-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function emptyFindings(t) {
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
}
function write(t, rel, body) {
  const abs = join(t, rel); mkdirSync(join(abs, ".."), { recursive: true }); writeFileSync(abs, body);
}
function writeDraft(runDir, name, obj) { writeFileSync(join(runDir, name), JSON.stringify(obj)); }
function findings(t) { return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings; }
function expectReject(fn) {
  const orig = process.exit;
  process.exit = (code) => { throw new Error(`process.exit(${code})`); };
  try { assert.throws(fn, /process\.exit\(1\)/); } finally { process.exit = orig; }
}
const LONG = "x".repeat(160);

test("risk-rank: security-relevant files outrank boring ones", () => {
  const t = repo();
  write(t, "src/auth/login.js", "function login(){}\n");   // security-relevant path
  write(t, "src/util/format.js", "function fmt(){}\n");     // boring
  const { ranked } = rankFiles(t, { maxFiles: 10 });
  const auth = ranked.find((r) => r.filePath === "src/auth/login.js");
  const util = ranked.find((r) => r.filePath === "src/util/format.js");
  assert.ok(auth && util, "both ranked");
  assert.ok(auth.score > util.score, "the auth file scores higher");
  assert.ok(auth.reasons.includes("security-relevant-path"));
});

test("deep-scan prepare: ranks files, reports unreadCount honestly under a budget", () => {
  const t = repo();
  for (let i = 0; i < 6; i += 1) write(t, `src/m${i}.js`, `function f${i}(){}\n`);
  write(t, "src/payment.js", "function charge(){}\n");
  const prep = prepareDeepScan(t, { maxFiles: 3 });
  assert.equal(prep.status, "prepared");
  assert.equal(prep.fileCount, 3, "budget respected");
  assert.ok(prep.unreadCount >= 4, "the rest are reported as unread, not dropped silently");
  const doc = JSON.parse(readFileSync(prep.prepPath, "utf8"));
  assert.equal(doc.files[0].filePath, "src/payment.js", "highest-risk file read first");
});

test("deep-scan finalize: promotes a read-derived finding; rejects bad verdict + finding w/o CWE", () => {
  const t = repo(); emptyFindings(t);
  write(t, "src/api.js", "function run(q){ return db.run('SELECT '+q); }\n");
  const prep = prepareDeepScan(t, { maxFiles: 5 });

  // A valid deep-read finding (a custom db.run() wrapper no pattern would catch).
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "d1", bugClass: "sqli", verdict: "finding", severity: "high", cwe: "CWE-89",
      title: "SQLi via custom db.run wrapper",
      rationale: `run(q) concatenates the untrusted q directly into a SQL string passed to the project's db.run helper; no parameterization or escaping anywhere on the path ${LONG}`,
      evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }
  ] });
  const res = finalizeDeepScan(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.equal(findings(t).filter((f) => f.source === "deep-scan").length, 1);

  // finding without a CWE is refused.
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "d2", verdict: "finding", rationale: LONG, evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }
  ] });
  expectReject(() => finalizeDeepScan(t, prep.runDir));

  // bad verdict is refused.
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [{ deepId: "d3", verdict: "nope", rationale: LONG }] });
  expectReject(() => finalizeDeepScan(t, prep.runDir));
});
