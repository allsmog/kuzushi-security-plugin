// Contracts for /deep-hunt — the interprocedural hypothesis hunt. The prepare must
// rank TRACE ANCHORS (entry points + dangerous sinks) with their enclosing function
// and surface the walk CLIs + an honest unanchored remainder; the finalize must gate
// a "finding" on a CONFIRMED CROSS-FILE PATH (≥2 hops, ≥2 files) and store that path
// as the finding's evidenceGraph. This is the cross-file recall lever, so its
// determinism (anchoring + the interprocedural-path gate) is what matters.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { ripgrepPath } from "../scripts/lib/ripgrep.mjs";
import { prepareDeepHunt } from "../scripts/cmd/deep-hunt-prepare.mjs";
import { finalizeDeepHunt } from "../scripts/cmd/deep-hunt-finalize.mjs";

const rgOk = (() => { try { return spawnSync(ripgrepPath(), ["--version"], { stdio: "ignore" }).status === 0; } catch { return false; } })();
const LONG = "x".repeat(160);

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-deephunt-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function emptyFindings(t) {
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
}
function write(t, rel, body) { const abs = join(t, rel); mkdirSync(join(abs, ".."), { recursive: true }); writeFileSync(abs, body); }
function findings(t) { return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings; }
function runDirWith(t, draft) {
  const rd = join(t, "rd"); mkdirSync(rd, { recursive: true });
  writeFileSync(join(rd, "draft.deep-hunt.json"), JSON.stringify(draft));
  return rd;
}
function expectReject(fn) {
  const orig = process.exit;
  process.exit = (code) => { throw new Error(`process.exit(${code})`); };
  try { assert.throws(fn, /process\.exit\(1\)/); } finally { process.exit = orig; }
}

// ---- prepare: anchors + enclosing functions + honest budget -----------------

test("deep-hunt prepare: ranks source + sink anchors with their enclosing function", { skip: !rgOk }, () => {
  const t = repo();
  write(t, "src/handler.js", "app.get('/u', function (req) {\n  return lookup(req.query.id);\n});\n");
  write(t, "src/db.js", "function lookup(id){\n  return db.query('SELECT '+id);\n}\n");
  const prep = prepareDeepHunt(t, { maxAnchors: 10 });
  assert.equal(prep.status, "prepared");
  const doc = JSON.parse(readFileSync(prep.prepPath, "utf8"));
  assert.ok(doc.anchors.some((a) => a.kind === "source" && a.filePath === "src/handler.js"), "entry-point source anchored");
  assert.ok(doc.anchors.some((a) => a.kind === "sink" && a.filePath === "src/db.js"), "db.query sink anchored");
  const sink = doc.anchors.find((a) => a.kind === "sink");
  assert.ok(sink.enclosingFunction && sink.enclosingFunction.name === "lookup", "the sink anchor carries its enclosing function");
  assert.ok(doc.reachability.calleesCli.endsWith("callees.mjs") && doc.reachability.callersCli.endsWith("callers.mjs"), "walk CLIs surfaced");
  assert.equal(doc.budget.maxHops, 4);
});

test("deep-hunt prepare: caps anchors and reports the unanchored remainder honestly", { skip: !rgOk }, () => {
  const t = repo();
  for (let i = 0; i < 8; i += 1) write(t, `src/r${i}.js`, `app.get('/p${i}', (req) => { sink(req.query.x); });\n`);
  const prep = prepareDeepHunt(t, { maxAnchors: 4 });
  assert.ok(prep.anchorCount <= 4, "anchor budget respected");
  assert.ok(prep.unanchoredCount >= 1, "the rest are reported as unanchored, not dropped silently");
});

// ---- finalize: the interprocedural-path gate --------------------------------

test("deep-hunt finalize: promotes a confirmed cross-file flow with the path as evidenceGraph", () => {
  const t = repo(); emptyFindings(t);
  const rd = runDirWith(t, { candidates: [{
    huntId: "dh1", title: "SQLi: req.query.id → db.query", cwe: "CWE-89", severity: "high",
    verdict: "finding", evidenceLevel: "linked",
    source: { filePath: "src/handler.js", startLine: 2 },
    sink: { filePath: "src/db.js", startLine: 2 },
    path: [
      { filePath: "src/handler.js", startLine: 2, role: "source: req.query.id" },
      { filePath: "src/svc.js", startLine: 3, role: "passes id to lookup()" },
      { filePath: "src/db.js", startLine: 2, role: "sink: db.query('SELECT '+id)" }
    ],
    rationale: `req.query.id flows through svc.lookup() into db.query concatenated into SQL with no parameterization ${LONG}`,
    selfCheck: "A parameterized query or escaping guard on the path would make this safe; none exists between source and sink."
  }] });
  const res = finalizeDeepHunt(t, rd);
  assert.equal(res.status, "completed");
  const f = findings(t).find((x) => x.source === "deep-hunt");
  assert.ok(f, "promoted under source deep-hunt");
  assert.equal(f.status, "open", "verdict finding → status open");
  assert.equal(f.evidenceGraph.nodes.length, 3, "all hops stored as graph nodes");
  assert.equal(f.evidenceGraph.edges.length, 2, "edges connect the hops in order");
  assert.equal(f.evidence.length, 2, "source + sink as the evidence anchors");
});

test("deep-hunt finalize: a single-file 'finding' is rejected (must be interprocedural)", () => {
  const t = repo(); emptyFindings(t);
  const rd = runDirWith(t, { candidates: [{
    huntId: "dh2", title: "single-file", cwe: "CWE-89", verdict: "finding", rationale: LONG,
    selfCheck: "no guard present on the path between the two same-file points at all here",
    path: [
      { filePath: "src/a.js", startLine: 1, role: "source" },
      { filePath: "src/a.js", startLine: 9, role: "sink" }
    ]
  }] });
  expectReject(() => finalizeDeepHunt(t, rd));
});

test("deep-hunt finalize: a 'finding' with <2 hops is rejected", () => {
  const t = repo(); emptyFindings(t);
  const rd = runDirWith(t, { candidates: [{
    huntId: "dh3", title: "one hop", cwe: "CWE-89", verdict: "finding", rationale: LONG,
    selfCheck: "the guard that would stop this is absent on the only hop recorded here ok",
    path: [{ filePath: "src/a.js", startLine: 1, role: "source+sink" }]
  }] });
  expectReject(() => finalizeDeepHunt(t, rd));
});

test("deep-hunt finalize: bad verdict and finding-without-selfCheck are rejected", () => {
  const t = repo(); emptyFindings(t);
  expectReject(() => finalizeDeepHunt(t, runDirWith(t, { candidates: [{ huntId: "b", verdict: "nope", rationale: LONG }] })));
  const noSelf = runDirWith(t, { candidates: [{
    huntId: "ns", title: "x", cwe: "CWE-89", verdict: "finding", rationale: LONG,
    path: [{ filePath: "src/a.js", startLine: 1, role: "s" }, { filePath: "src/b.js", startLine: 2, role: "k" }]
  }] });
  expectReject(() => finalizeDeepHunt(t, noSelf));
});

test("deep-hunt finalize: a candidate (incomplete path) is promoted without the finding gate", () => {
  const t = repo(); emptyFindings(t);
  const rd = runDirWith(t, { candidates: [{
    huntId: "c1", title: "plausible but unconfirmed", verdict: "candidate", evidenceLevel: "candidate",
    source: { filePath: "src/h.js", startLine: 1 }, sink: { filePath: "src/d.js", startLine: 5 },
    rationale: `source and sink for the same CWE exist and plausibly relate but propagation across the gap was not confirmed ${LONG}`
  }] });
  const res = finalizeDeepHunt(t, rd);
  assert.equal(res.status, "completed");
  const f = findings(t).find((x) => x.source === "deep-hunt" && x.refId === "c1");
  assert.ok(f, "candidate promoted");
  assert.equal(f.status, "needs-evidence", "verdict candidate → status needs-evidence");
});
