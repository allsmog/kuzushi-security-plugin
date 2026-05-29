// Contracts for the risk-ranking lib (scripts/lib/risk.mjs) and the /report
// deterministic transform (scripts/cmd/report-build.mjs). Engine-independent:
// no docker/codeql/joern, no LLM — pure rendering of an existing findings index.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { upsertFindings, patchFindings } from "../scripts/lib/findings.mjs";
import { storeFor, atomicWrite } from "../scripts/lib/artifact-store.mjs";
import { scoreFinding, rankFindings } from "../scripts/lib/risk.mjs";
import { buildReport } from "../scripts/cmd/report-build.mjs";

function tmp() { return mkdtempSync(join(tmpdir(), "kz-report-")); }
const finding = (over = {}) => ({
  source: "threat-hunt", refId: "f", title: "t", severity: "high", cwe: "89",
  verdict: "exploitable", status: "open", proofState: "open",
  evidence: [{ filePath: "a.js", startLine: 1 }], rationale: "x", nextChecks: [], ...over
});

// ---- risk scoring -----------------------------------------------------------

test("scoreFinding: severity and proof state both raise the score", () => {
  const lowOpen = scoreFinding(finding({ severity: "low", proofState: "open" }));
  const critOpen = scoreFinding(finding({ severity: "critical", proofState: "open" }));
  const critProven = scoreFinding(finding({ severity: "critical", proofState: "proven" }));
  assert.ok(critOpen > lowOpen, "critical outranks low at the same proof state");
  assert.ok(critProven > critOpen, "proven outranks open at the same severity");
});

test("scoreFinding: a proven high beats an open critical (proof dominates a one-step severity gap)", () => {
  const provenHigh = scoreFinding(finding({ severity: "high", proofState: "proven" }));
  const openCrit = scoreFinding(finding({ severity: "critical", proofState: "open" }));
  assert.ok(provenHigh > openCrit, `${provenHigh} should beat ${openCrit}`);
});

test("scoreFinding: mem-exploitability tier and blast radius add, clamped to 100", () => {
  const base = scoreFinding(finding({ severity: "high", proofState: "open" }));
  const withTier = scoreFinding(finding({ severity: "high", proofState: "open", exploitability: { tier: "likely-code-exec" } }));
  assert.ok(withTier > base, "a code-exec tier raises the score");
  const withBlast = scoreFinding(finding({ severity: "high", proofState: "open" }), { blastRadius: 500 });
  assert.ok(withBlast > base, "a hub location raises the score");
  const maxed = scoreFinding(finding({ severity: "critical", proofState: "proven", exploitability: { tier: "likely-code-exec" } }), { blastRadius: 9999 });
  assert.ok(maxed <= 100, "score never exceeds 100");
});

test("rankFindings: orders by score, is stable, and assigns 1-based ranks", () => {
  const fs = [
    finding({ fingerprint: "b", severity: "low", proofState: "lead" }),
    finding({ fingerprint: "a", severity: "critical", proofState: "proven" }),
    finding({ fingerprint: "c", severity: "medium", proofState: "open" })
  ];
  const ranked = rankFindings(fs);
  assert.equal(ranked[0].finding.fingerprint, "a", "highest risk first");
  assert.equal(ranked[0].rank, 1);
  assert.equal(ranked[2].rank, 3);
  assert.ok(ranked[0].score >= ranked[1].score && ranked[1].score >= ranked[2].score, "monotonically non-increasing");
});

// ---- report rendering -------------------------------------------------------

test("buildReport throws before any findings index exists", () => {
  assert.throws(() => buildReport(tmp(), {}), /not found/);
});

test("buildReport renders a prioritized markdown report with the key sections", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "sqli", title: "SQL injection", severity: "critical", status: "proven", proofState: "proven", cwe: "89", evidence: [{ filePath: "src/db.ts", startLine: 10 }] }),
    finding({ refId: "jwt", title: "JWT alg none", severity: "high", status: "open", proofState: "open", cwe: "347", evidence: [{ filePath: "src/auth.ts", startLine: 5 }] })
  ]);
  const res = buildReport(t, {});
  assert.equal(res.findingCount, 2);
  assert.equal(res.actionableCount, 2);
  const md = readFileSync(res.reportPath, "utf8");
  assert.match(md, /# Security Review/);
  assert.match(md, /## Summary/);
  assert.match(md, /## Fix first/);
  // the proven critical must rank above the open high
  assert.ok(md.indexOf("SQL injection") < md.indexOf("JWT alg none"), "higher-risk finding listed first");
  assert.match(md, /CWE-89/);
  assert.match(md, /## Scope & provenance/);
});

test("buildReport excludes reviewed/noise by default and includes them with all:true", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "real", title: "Real bug", status: "open", proofState: "open" }),
    finding({ refId: "noise", title: "Library noise", status: "noise", proofState: "noise", verdict: "likely-library-noise", evidence: [{ filePath: "vendor/x.js", startLine: 2 }] })
  ]);
  const def = buildReport(t, {});
  assert.equal(def.actionableCount, 1, "noise is not actionable");
  const mdDefault = readFileSync(def.reportPath, "utf8");
  assert.doesNotMatch(mdDefault, /Library noise/, "noise hidden by default");
  assert.match(mdDefault, /1 noise/, "but counted in the resolved footer");

  const all = buildReport(t, { all: true });
  const mdAll = readFileSync(all.reportPath, "utf8");
  assert.match(mdAll, /Library noise/, "all:true surfaces resolved findings");
});

test("buildReport renders attack chains with display labels and cross-refs", () => {
  const t = tmp();
  upsertFindings(t, [
    finding({ refId: "a", title: "Bug A", status: "confirmed", proofState: "confirmed", evidence: [{ filePath: "a.ts", startLine: 1 }] }),
    finding({ refId: "b", title: "Bug B", status: "open", proofState: "open", evidence: [{ filePath: "b.ts", startLine: 2 }] })
  ]);
  const doc = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8"));
  const members = doc.findings.map((f) => f.fingerprint);
  atomicWrite(storeFor(t).chainsPath, JSON.stringify({
    version: "1.0", chainCount: 1,
    chains: [{ chainId: "chain-xyz", title: "A then B", members, severity: "high", narrative: "y".repeat(80) }]
  }));
  patchFindings(t, members.map((fp) => ({ fingerprint: fp, chains: ["chain-xyz"] })));
  const res = buildReport(t, {});
  assert.equal(res.chainCount, 1);
  const md = readFileSync(res.reportPath, "utf8");
  assert.match(md, /## Attack chains \(1\)/);
  assert.match(md, /C-1 · A then B/);
  assert.match(md, /chain C-1/, "members cross-reference the chain label");
});

test("buildReport uses code-graph caller counts for blast-radius ranking when present", () => {
  const t = tmp();
  upsertFindings(t, [finding({ refId: "hub", title: "Hub bug", severity: "medium", status: "open", proofState: "open", evidence: [{ filePath: "src/core.ts", startLine: 50 }] })]);
  atomicWrite(storeFor(t).codeGraphPath, JSON.stringify({
    symbols: [{ name: "coreHandler", file: "src/core.ts", line: 40, callerCount: 120 }], entryPoints: []
  }));
  const res = buildReport(t, {});
  const md = readFileSync(res.reportPath, "utf8");
  assert.match(md, /blast 120/, "the nearest-preceding symbol's caller count is shown as blast radius");
  assert.doesNotMatch(md, /Blast-radius unavailable/, "the no-code-graph note is suppressed when a graph exists");
});

test("buildReport emits HTML only with html:true", () => {
  const t = tmp();
  upsertFindings(t, [finding({ status: "open", proofState: "open" })]);
  const noHtml = buildReport(t, {});
  assert.equal(noHtml.htmlPath, null);
  const withHtml = buildReport(t, { html: true });
  assert.ok(withHtml.htmlPath, "html path returned");
  const html = readFileSync(withHtml.htmlPath, "utf8");
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Security Review/);
});

test("buildReport handles an empty findings index without throwing", () => {
  const t = tmp();
  // write a valid but empty index
  atomicWrite(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", generatedAt: "now", target: t, findings: [], summary: { total: 0, byStatus: {}, byVerdict: {} } }));
  const res = buildReport(t, {});
  assert.equal(res.findingCount, 0);
  const md = readFileSync(res.reportPath, "utf8");
  assert.match(md, /No findings recorded yet/);
});
