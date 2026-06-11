// Regression contracts for the producers added without committed coverage:
// /iac, /authz, /sharp-edges, /crypto-review, /supply-chain, /traffic-map,
// /code-graph, /path-solve. Each exercises the deterministic prepare (candidate
// detection / parsing) and finalize (validation + promotion to findings.json) —
// the same scratch-repo flows used during development, now pinned. Engine-free
// (no docker/joern/z3); the heuristic/parse paths only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { upsertFindings } from "../scripts/lib/findings.mjs";
import { prepareIac } from "../scripts/cmd/iac-prepare.mjs";
import { finalizeIac as _fiac } from "../scripts/cmd/iac-finalize.mjs";
import { prepareAuthz } from "../scripts/cmd/authz-prepare.mjs";
import { finalizeAuthz } from "../scripts/cmd/authz-finalize.mjs";
import { prepareSharpEdges } from "../scripts/cmd/sharp-edges-prepare.mjs";
import { finalizeSharpEdges } from "../scripts/cmd/sharp-edges-finalize.mjs";
import { prepareCryptoReview } from "../scripts/cmd/crypto-review-prepare.mjs";
import { finalizeCryptoReview } from "../scripts/cmd/crypto-review-finalize.mjs";
import { prepareSupplyChain } from "../scripts/cmd/supply-chain-prepare.mjs";
import { finalizeSupplyChain } from "../scripts/cmd/supply-chain-finalize.mjs";
import { prepareTrafficMap } from "../scripts/cmd/traffic-map-prepare.mjs";
import { finalizeTrafficMap } from "../scripts/cmd/traffic-map-finalize.mjs";
import { buildCodeGraph } from "../scripts/cmd/code-graph-build.mjs";
import { preparePathSolve } from "../scripts/cmd/path-solve-prepare.mjs";
import { assemblePathSolve } from "../scripts/cmd/path-solve-assemble.mjs";
import { prepareLogicHunt } from "../scripts/cmd/logic-hunt-prepare.mjs";
import { finalizeLogicHunt } from "../scripts/cmd/logic-hunt-finalize.mjs";
import { prepareBinaryRecon } from "../scripts/cmd/binary-recon-prepare.mjs";
import { finalizeBinaryRecon } from "../scripts/cmd/binary-recon-finalize.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-prod-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function emptyFindings(t) {
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
}
function writeDraft(runDir, name, obj) {
  writeFileSync(join(runDir, name), JSON.stringify(obj));
}
function findings(t) {
  return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings;
}
const LONG = "x".repeat(160); // satisfies the ≥120/150-char rationale gates

// The finalize CLIs reject bad drafts via process.exit(1) (they're run headless),
// so stub exit→throw to assert the rejection in-process without killing the runner.
function expectReject(fn) {
  const orig = process.exit;
  process.exit = (code) => { throw new Error(`process.exit(${code})`); };
  try { assert.throws(fn, /process\.exit\(1\)/); } finally { process.exit = orig; }
}

// ---- /iac -------------------------------------------------------------------
test("iac: prepare detects container/network misconfig; finalize promotes + rejects bad verdict", () => {
  const t = repo(); emptyFindings(t);
  writeFileSync(join(t, "Dockerfile"), "FROM ubuntu:latest\nUSER root\n");
  writeFileSync(join(t, "main.tf"), 'resource "x" "y" { cidr_blocks = ["0.0.0.0/0"] }\n');
  const prep = prepareIac(t, {});
  assert.equal(prep.status, "prepared");
  assert.ok(prep.candidateCount >= 2, "detects unpinned image + open cidr");

  writeDraft(prep.runDir, "draft.iac.json", { candidates: [
    { iacId: "i1", surface: "container", verdict: "finding", cwe: "CWE-250",
      rationale: `privileged root container ${LONG}`, evidenceAnchors: [{ filePath: "Dockerfile", startLine: 2 }] }
  ] });
  const res = _fiac(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.equal(findings(t).filter((f) => f.source === "iac").length, 1);

  writeDraft(prep.runDir, "draft.iac.json", { candidates: [{ iacId: "bad", verdict: "totally-wrong", rationale: LONG }] });
  expectReject(() => _fiac(t, prep.runDir));
});

// ---- /authz -----------------------------------------------------------------
test("authz: prepare finds endpoint+idor; finalize defaults idor → CWE-639", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/o.js"), "app.get('/orders/:id', (req,res)=>{ const o = Order.findById(req.params.id); res.json(o); });\n");
  const prep = prepareAuthz(t, {});
  assert.equal(prep.status, "prepared");
  assert.ok(prep.candidateCount >= 1);

  writeDraft(prep.runDir, "draft.authz.json", { candidates: [
    { authzId: "a1", authzClass: "idor", verdict: "finding",
      rationale: `no ownership scope on Order.findById ${LONG}`, evidenceAnchors: [{ filePath: "src/o.js", startLine: 1 }] }
  ] });
  finalizeAuthz(t, prep.runDir);
  const f = findings(t).find((x) => x.source === "authz");
  assert.equal(f.cwe, "CWE-639", "idor default CWE");
  assert.equal(f.status, "open");
});

test("authz: severity is DERIVED from preconditions × access level, not the agent's claim", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/o.js"), "app.get('/orders/:id',(req,res)=>{Order.findById(req.params.id)})\n");
  const prep = prepareAuthz(t, {});
  // Agent CLAIMS critical but supplies 0 preconditions + unauthenticated-remote → derives HIGH.
  writeDraft(prep.runDir, "draft.authz.json", { candidates: [
    { authzId: "a1", authzClass: "idor", verdict: "finding", severity: "critical",
      preconditions: [], accessLevel: "unauthenticated-remote",
      rationale: `no ownership scope on Order.findById ${LONG}`, evidenceAnchors: [{ filePath: "src/o.js", startLine: 1 }] }
  ] });
  finalizeAuthz(t, prep.runDir);
  const f = findings(t).find((x) => x.source === "authz");
  assert.equal(f.severity, "high", "derived from the table, not the claimed 'critical'");
  assert.equal(f.severityBasis.boosted, false);
  assert.equal(f.severityBasis.claimedJudgment.delta, 1, "claimed 'critical' is one step over derived 'high' (borderline)");
});

test("authz: a 3+ precondition local-only finding derives LOW and flags an inflated 'critical' claim", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/o.js"), "app.get('/admin/:id',(req,res)=>{Order.findById(req.params.id)})\n");
  const prep = prepareAuthz(t, {});
  writeDraft(prep.runDir, "draft.authz.json", { candidates: [
    { authzId: "a1", authzClass: "idor", verdict: "finding", severity: "critical",
      preconditions: ["admin session", "feature flag on", "victim id known"], accessLevel: "local-only",
      rationale: `deep behind admin + flag ${LONG}`, evidenceAnchors: [{ filePath: "src/o.js", startLine: 1 }] }
  ] });
  finalizeAuthz(t, prep.runDir);
  const f = findings(t).find((x) => x.source === "authz");
  assert.equal(f.severity, "low", "3+ preconditions and local-only both floor it at LOW");
  assert.ok(f.severityBasis.claimedJudgment.score < 0, "claimed 'critical' over derived 'low' is flagged inflation");
});

test("authz: rejected verdict must name the protecting check", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src")); writeFileSync(join(t, "src/o.js"), "app.get('/x',(req,res)=>{Order.findById(req.params.id)})\n");
  const prep = prepareAuthz(t, {});
  writeDraft(prep.runDir, "draft.authz.json", { candidates: [
    { authzId: "a1", authzClass: "idor", verdict: "rejected", rationale: `looks fine ${LONG}` } // no authz keyword
  ] });
  expectReject(() => finalizeAuthz(t, prep.runDir));
});

// ---- /logic-hunt ------------------------------------------------------------
test("logic-hunt: prepare seeds from deep-context invariants + probes; finalize promotes a violation", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/wallet.js"), "function transfer(a,b,amount){ a.balance -= amount; b.balance += amount; }\n");
  // A deep-context invariant becomes the strongest seed.
  writeFileSync(join(storeFor(t).root, "deep-context.json"), JSON.stringify({
    invariants: [{ statement: "a transfer debits and credits atomically", logicClass: "atomicity" }]
  }));
  const prep = prepareLogicHunt(t, {});
  assert.equal(prep.status, "prepared");
  assert.ok(prep.invariantSeedCount >= 1, "invariant seeded as a candidate");
  assert.ok(prep.candidateCount >= 1);

  writeDraft(prep.runDir, "draft.logic-hunt.json", { candidates: [
    { logicId: "l1", logicClass: "atomicity", verdict: "violation", severity: "high", exposure: "authenticated",
      violationScenario: "crash between the debit and the credit line leaves money destroyed",
      rationale: `transfer() mutates a.balance then b.balance with no transaction; an interruption between the two writes debits the sender without crediting the recipient. ${LONG}`,
      evidenceAnchors: [{ filePath: "src/wallet.js", startLine: 1 }] }
  ] });
  const res = finalizeLogicHunt(t, prep.runDir);
  assert.equal(res.status, "completed");
  const f = findings(t).find((x) => x.source === "logic-hunt");
  assert.equal(f.status, "open");
  assert.equal(f.exposure, "authenticated"); // flows into priority ranking
  assert.equal(f.cwe, "CWE-840"); // business-logic default
});

test("logic-hunt: a 'holds' verdict must name the enforcement; 'violation' needs a scenario", () => {
  const t = repo(); emptyFindings(t);
  const prep = prepareLogicHunt(t, {});
  // ≥200 chars so the LENGTH gate passes and the verdict-specific gate is what fires.
  // 'holds' rationale that never names an enforcement (no lock/constraint/check/...).
  const holdsNoEnforcement = "i read the surrounding handler and its helpers and the property appeared upheld throughout; i could not produce a counterexample in the time spent, so i am recording it as holding for now pending a deeper read of persistence";
  assert.ok(holdsNoEnforcement.length >= 200);
  writeDraft(prep.runDir, "draft.logic-hunt.json", { candidates: [
    { logicId: "l1", logicClass: "atomicity", verdict: "holds", rationale: holdsNoEnforcement }
  ] });
  expectReject(() => finalizeLogicHunt(t, prep.runDir)); // holds without a named enforcement
  // 'violation' with a long rationale + evidence but NO violationScenario → rejected.
  writeDraft(prep.runDir, "draft.logic-hunt.json", { candidates: [
    { logicId: "l2", logicClass: "ordering", verdict: "violation", rationale: `the ordering can be abused ${LONG}`,
      evidenceAnchors: [{ filePath: "x.js", startLine: 1 }] }
  ] });
  expectReject(() => finalizeLogicHunt(t, prep.runDir)); // violation without a violationScenario
});

// ---- /sharp-edges -----------------------------------------------------------
test("sharp-edges: prepare flags jwt alg:none; finalize promotes", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/a.js"), "jwt.verify(raw, key, { algorithms: ['HS256','none'] });\n");
  const prep = prepareSharpEdges(t, {});
  assert.ok(prep.candidateCount >= 1, "alg:none detected");
  writeDraft(prep.runDir, "draft.sharp-edges.json", { candidates: [
    { edgeId: "e1", category: "algorithm-selection", verdict: "finding", cwe: "CWE-347",
      rationale: `alg:none allows forged tokens ${LONG}`, evidenceAnchors: [{ filePath: "src/a.js", startLine: 1 }] }
  ] });
  finalizeSharpEdges(t, prep.runDir);
  assert.equal(findings(t).find((f) => f.source === "sharp-edges").category, "algorithm-selection");
});

// ---- /crypto-review ---------------------------------------------------------
test("crypto-review: prepare detects timing+rng (bidirectional); finalize rejects invalid category", () => {
  const t = repo(); emptyFindings(t);
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/c.js"), "if (received == expected_hmac) ok();\nconst token = Math.random().toString(36);\n");
  const prep = prepareCryptoReview(t, {});
  const cats = new Set(JSON.parse(readFileSync(prep.prepPath, "utf8")).candidates.map((c) => c.category));
  assert.ok(cats.has("timing-side-channel"), "secret==compare caught either-side");
  assert.ok(cats.has("weak-crypto-rng"), "Math.random→token caught either-side");

  writeDraft(prep.runDir, "draft.crypto-review.json", { candidates: [
    { cryptoId: "c1", category: "not-a-category", verdict: "finding", rationale: LONG, evidenceAnchors: [{ filePath: "src/c.js", startLine: 1 }] }
  ] });
  expectReject(() => finalizeCryptoReview(t, prep.runDir));
});

// ---- /supply-chain ----------------------------------------------------------
test("supply-chain: parses manifests; finalize promotes high→finding, medium→candidate, low not promoted", () => {
  const t = repo(); emptyFindings(t);
  writeFileSync(join(t, "package.json"), JSON.stringify({ dependencies: { left: "1", mid: "1", ok: "1" } }));
  const prep = prepareSupplyChain(t, {});
  assert.ok(prep.depCount >= 3);
  writeDraft(prep.runDir, "draft.supply-chain.json", { dependencies: [
    { name: "left", ecosystem: "npm", manifest: "package.json", line: 1, riskTier: "high", rationale: `single maintainer ${LONG}` },
    { name: "mid", ecosystem: "npm", manifest: "package.json", line: 1, riskTier: "medium", rationale: `stale ${LONG}` },
    { name: "ok", ecosystem: "npm", manifest: "package.json", line: 1, riskTier: "low", rationale: `healthy ${LONG}` }
  ] });
  const res = finalizeSupplyChain(t, prep.runDir);
  assert.equal(res.promotedCount, 2, "low is recorded, not promoted");
  const fs = findings(t).filter((f) => f.source === "supply-chain");
  assert.equal(fs.find((f) => f.refId === "npm:left").status, "open");
  assert.equal(fs.find((f) => f.refId === "npm:mid").status, "needs-evidence");
});

// ---- /traffic-map -----------------------------------------------------------
test("traffic-map: parses HAR into deduped endpoints; finalize writes map + promotes shadow gap", () => {
  const t = repo(); emptyFindings(t);
  writeFileSync(join(t, "capture.har"), JSON.stringify({ log: { entries: [
    { request: { method: "GET", url: "https://h/orders/1?x=1", headers: [] } },
    { request: { method: "GET", url: "https://h/orders/1?x=1", headers: [] } },
    { request: { method: "POST", url: "https://h/admin", headers: [], postData: { params: [{ name: "role" }] } } }
  ] } }));
  const prep = prepareTrafficMap(t, {});
  assert.equal(prep.endpointCount, 2, "GET /orders/1 deduped, POST /admin");
  writeDraft(prep.runDir, "draft.traffic-map.json", {
    correlations: [{ method: "GET", path: "/orders/1", status: "mapped" }, { method: "POST", path: "/admin", status: "shadow" }],
    candidates: [{ refId: "shadow-admin", method: "POST", path: "/admin", verdict: "candidate", rationale: `shadow admin endpoint ${LONG}` }]
  });
  const res = finalizeTrafficMap(t, prep.runDir);
  assert.equal(res.summary.shadow, 1);
  assert.ok(existsSync(storeFor(t).trafficMapPath));
  assert.equal(findings(t).filter((f) => f.source === "traffic-map").length, 1);
});

// ---- /code-graph ------------------------------------------------------------
test("code-graph: heuristic backend ranks symbols by real call-site count", () => {
  const t = repo();
  mkdirSync(join(t, "src"));
  writeFileSync(join(t, "src/u.c"),
    "int validate(char*s){return s[0];}\nint parse(char*s){return validate(s)+validate(s);}\nint handle(char*s){return parse(s);}\n");
  const res = buildCodeGraph(t, { forceHeuristic: true });
  assert.equal(res.backend, "ripgrep-heuristic");
  const g = JSON.parse(readFileSync(storeFor(t).codeGraphPath, "utf8"));
  const v = g.symbols.find((s) => s.name === "validate");
  assert.equal(v.callerCount, 2, "validate() called twice by parse()");
  assert.equal(g.symbols[0].name, "validate", "ranked by callerCount");
});

// ---- /path-solve ------------------------------------------------------------
test("path-solve: selects needs-trace findings; finalize attaches pathSolution + payload gate", () => {
  const t = repo();
  upsertFindings(t, [{ source: "systems-hunt", refId: "s1", title: "ovf", severity: "high", cwe: "787",
    verdict: "needs-active-agent-trace", evidence: [{ filePath: "h.c", startLine: 1 }], rationale: "x" }]);
  const prep = preparePathSolve(t, {});
  assert.equal(prep.candidateCount, 1, "needs-trace finding selected");
  const fp = findings(t)[0].fingerprint;

  // reachable:true without a payload is rejected
  writeDraft(prep.runDir, "draft.path-solve.json", { candidates: [
    { findingFingerprint: fp, backend: "llm", reachable: true, guards: [{ filePath: "h.c", line: 1, predicate: "len>64" }], rationale: LONG }
  ] });
  expectReject(() => assemblePathSolve(t, prep.runDir));

  // a complete solution attaches a pathSolution block (no verdict change)
  writeDraft(prep.runDir, "draft.path-solve.json", { candidates: [
    { findingFingerprint: fp, backend: "llm", reachable: true, guards: [{ filePath: "h.c", line: 1, predicate: "len>64", branchToTake: "true" }],
      solvedInput: { payload: "72 bytes" }, confidence: 0.7, rationale: LONG }
  ] });
  assemblePathSolve(t, prep.runDir);
  const f = findings(t)[0];
  assert.equal(f.pathSolution.reachable, true);
  assert.equal(f.verdict, "needs-active-agent-trace", "path-solve does not change the verdict");
});

// ---- end-to-end composition -------------------------------------------------
test("composition: multiple producers accrete into one findings.json by source", () => {
  const t = repo(); emptyFindings(t);
  // iac finding
  writeFileSync(join(t, "Dockerfile"), "FROM x:latest\n");
  let prep = prepareIac(t, {});
  writeDraft(prep.runDir, "draft.iac.json", { candidates: [
    { iacId: "i", surface: "container", verdict: "finding", cwe: "CWE-1357", rationale: `unpinned ${LONG}`, evidenceAnchors: [{ filePath: "Dockerfile", startLine: 1 }] }
  ] });
  _fiac(t, prep.runDir);
  // sharp-edges finding
  mkdirSync(join(t, "src")); writeFileSync(join(t, "src/a.js"), "fetch(u,{rejectUnauthorized:false})\n");
  prep = prepareSharpEdges(t, {});
  writeDraft(prep.runDir, "draft.sharp-edges.json", { candidates: [
    { edgeId: "e", category: "dangerous-defaults", verdict: "finding", cwe: "CWE-295", rationale: `tls off ${LONG}`, evidenceAnchors: [{ filePath: "src/a.js", startLine: 1 }] }
  ] });
  finalizeSharpEdges(t, prep.runDir);

  const doc = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8"));
  assert.equal(doc.summary.bySource ? undefined : undefined, undefined); // summary shape tolerated
  const sources = new Set(doc.findings.map((f) => f.source));
  assert.ok(sources.has("iac") && sources.has("sharp-edges"), "both producers' findings coexist in the shared index");
  assert.equal(doc.findings.length, 2);
});

// ---- /binary-recon ----------------------------------------------------------
test("binary-recon: prepare detects an ELF by magic bytes; finalize promotes + rejects bad verdict", () => {
  const t = repo(); emptyFindings(t);
  // Minimal ELF magic header (enough for detection; triage degrades gracefully).
  mkdirSync(join(t, "bin"));
  writeFileSync(join(t, "bin/app"), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0]));
  const prep = prepareBinaryRecon(t, {});
  assert.equal(prep.status, "prepared");
  assert.ok(prep.candidateCount >= 1, "detects the ELF artifact");

  writeDraft(prep.runDir, "draft.binary-recon.json", { candidates: [
    { binaryId: "b1", binaryClass: "rwx-segment", verdict: "finding", cwe: "CWE-1340",
      rationale: `binary ships a writable+executable segment with no JIT justification ${LONG}`,
      evidenceAnchors: [{ filePath: "bin/app" }] }
  ] });
  const res = finalizeBinaryRecon(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.equal(findings(t).filter((f) => f.source === "binary-recon").length, 1);

  writeDraft(prep.runDir, "draft.binary-recon.json", { candidates: [{ binaryId: "b2", verdict: "nope", rationale: LONG }] });
  expectReject(() => finalizeBinaryRecon(t, prep.runDir));
});

test("binary-recon: no binaries → no-candidates", () => {
  const t = repo();
  writeFileSync(join(t, "readme.txt"), "just text\n");
  const prep = prepareBinaryRecon(t, {});
  assert.equal(prep.status, "no-candidates");
});
