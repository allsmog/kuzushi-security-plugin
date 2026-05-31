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
import { extractObligations } from "../scripts/lib/sink-obligations.mjs";

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

// --- lifetime-free obligation (the UAF lever) — unit-gate the new rule ----------------------
test("obligations: a free() emits a lifetime-free obligation; a commented free does not", () => {
  const t = repo();
  write(t, "src/c.c", "void g(struct s *p){\n  free(p);\n  // free(p)\n  return;\n}\n");
  const free = extractObligations(t, "src/c.c").filter((o) => o.kind === "lifetime-free");
  assert.equal(free.length, 1, "the real free() is flagged, the comment is not");
  assert.equal(free[0].line, 2);
});

test("obligations: a realloc(n*sz) line tags alloc-arith, not lifetime-free (first-match ordering)", () => {
  const t = repo();
  write(t, "src/r.c", "void f(int n,int sz){ char *p = realloc(p, n*sz); }\n");
  const obs = extractObligations(t, "src/r.c");
  assert.ok(obs.some((o) => o.kind === "alloc-arith"), "realloc tags alloc-arith");
  assert.ok(!obs.some((o) => o.kind === "lifetime-free"), "and NOT lifetime-free — the more specific rule wins first");
});

test("obligations: even-stride sampling reaches late-file free sites (cap not top-biased — the xackdel property)", () => {
  const t = repo();
  const lines = Array.from({ length: 120 }, (_, i) => `  free(p${i});`); // 120 lifetime-free sites spread down the file
  write(t, "src/long.c", `void f(){\n${lines.join("\n")}\n}\n`);
  const obs = extractObligations(t, "src/long.c", { cap: 32 });
  assert.equal(obs.length, 32, "capped to 32");
  assert.ok(obs.every((o) => o.kind === "lifetime-free"), "all free sites tagged lifetime-free");
  const maxLine = Math.max(...obs.map((o) => o.line));
  assert.ok(maxLine > 90, `even-stride reaches the late file (max sampled free at line ${maxLine} of ~122), not just the first 32`);
});

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
      selfCheck: "A parameterized query or an escaping/whitelist guard would make this safe; neither is present on the path from q to db.run.",
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

test("deep-scan finalize: a finding without selfCheck is rejected (self-falsification gate)", () => {
  const t = repo(); emptyFindings(t);
  write(t, "src/api.js", "function run(q){ return db.run('SELECT '+q); }\n");
  const prep = prepareDeepScan(t, { maxFiles: 5 });
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "x", verdict: "finding", cwe: "CWE-89", rationale: LONG,
      evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }  // no selfCheck
  ] });
  expectReject(() => finalizeDeepScan(t, prep.runDir));
});

test("risk-rank: an entry-point-dense file outranks a keyword-only file (reachability over keyword)", () => {
  const t = repo();
  // handler.js DEFINES routes (attacker surface) but has no security keyword in its path
  write(t, "lib/handler.js", "app.post('/a',(q,r)=>{}); app.get('/b',(q,r)=>{}); app.put('/c',(q,r)=>{});\n");
  // auth_helpers.js matches the keyword hint but defines no entry points
  write(t, "lib/auth_helpers.js", "function fmt(s){ return s.trim(); }\n");
  const { ranked } = rankFiles(t, { maxFiles: 10 });
  const h = ranked.find((r) => r.filePath === "lib/handler.js");
  const a = ranked.find((r) => r.filePath === "lib/auth_helpers.js");
  assert.ok(h && a, "both ranked");
  assert.ok(h.score > a.score, "entry-point-dense file outranks the keyword-only file");
  assert.ok(h.reasons.some((x) => x.startsWith("entry-defs")), "entry-defs is the reason");
});
