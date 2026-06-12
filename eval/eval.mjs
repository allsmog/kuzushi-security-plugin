#!/usr/bin/env node
// LLM-in-the-loop eval: drives the REAL kuzushi agents via `claude -p` and scores
// them blind against fix-derived CVE ground truth.
//
// This is the first VALID measurement of the plugin's bug-finding. Prior "tests"
// either skipped the LLM (bench/) or had a human author the agent drafts; here the
// deterministic prepare/finalize run locally and a fresh `claude -p` session plays
// each forked agent (deep-scanner, verifier) with no foreknowledge — the repo is
// copied to a scratch dir with no expected.json sibling, so the agent can't peek.
//
// A LOW number here is a valid, honest result — the baseline the levers must beat —
// not a test failure. The harness exits non-zero only on its own failure.

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, cpSync, existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { storeFor, readJsonIfPresent } from "../scripts/lib/artifact-store.mjs";
import { prepareDeepScan } from "../scripts/cmd/deep-scan-prepare.mjs";
import { finalizeDeepScan } from "../scripts/cmd/deep-scan-finalize.mjs";
import { prepareDeepHunt } from "../scripts/cmd/deep-hunt-prepare.mjs";
import { finalizeDeepHunt } from "../scripts/cmd/deep-hunt-finalize.mjs";
import { prepareVerify } from "../scripts/cmd/verify-prepare.mjs";
import { assembleVerify } from "../scripts/cmd/verify-assemble.mjs";
import { prepareFuzzDiscover } from "../scripts/cmd/fuzz-discover-prepare.mjs";
import { finalizeFuzzDiscover } from "../scripts/cmd/fuzz-discover-finalize.mjs";
import { runAgent, deepScanTask, deepHuntTask, verifyTask, fuzzDiscoverTask } from "./run-agent.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGIN = resolve(HERE, "..");
const CASES = join(PLUGIN, "bench", "cases");
const CVES = join(PLUGIN, "bench", "cves");
const LINE_TOL = 6;

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const MODEL = opt("--model", "sonnet");
const REPS = Number(opt("--reps", "1"));
const MAX_FILES = Number(opt("--maxFiles", "12"));
const MAX_ANCHORS = Number(opt("--maxAnchors", "24"));
// Per-agent kill ceiling. runAgent uses spawnSync, so this is a HARD cap on one forked
// agent's wall-clock — not an early-exit. The deep-scanner's per-obligation discharge
// (tree-sitter + concolic + LSP on every file) makes a real ~10-file repo run minutes;
// the old hardcoded 15-min default truncated large CVE cases BEFORE they wrote a draft
// (scored as a false "miss"). Default raised to 30 min; lower --maxFiles for big repos so
// each agent finishes (fewer files read deeply is also the proven recall lever).
const TIMEOUT_MS = Number(opt("--timeoutMs", "1800000"));
const MODE = opt("--mode", "deep-scan");     // deep-scan (whole-file reader) | deep-hunt (interprocedural)
const ONLY = opt("--case", null);
const FOCUS_FILES = (opt("--files", "") || "").split(",").map((s) => s.trim()).filter(Boolean);
const BATCH = Number(opt("--batch", "0"));  // >0: deep-read the routed files in small batches (depth), multi-pass
const CVE_MODE = args.includes("--cve");
// --cpgMemory: enable the discovery-time scoped-CPG memory pass (attaches cpgLeads for the
// sub-budget interpreter/parser subsystems). The routing-independent lane for memory bugs.
const CPG_MEMORY = args.includes("--cpgMemory");

export const norm = (p) => String(p ?? "").replace(/^\.\//, "");

export function expectedVulnerabilities(doc) {
  if (Array.isArray(doc.expected)) return doc.expected;
  if (Array.isArray(doc.expectations)) {
    return doc.expectations.filter((e) => e && e.kind !== "safe");
  }
  return [];
}

export function expectedSafeDecoys(doc) {
  if (Array.isArray(doc.expectations)) {
    return doc.expectations.filter((e) => e && e.kind === "safe");
  }
  return [];
}

// Read the findings index, tolerating its ABSENCE. A case whose only agent draft is
// rejected by a finalize (e.g. deep-hunt's ≥2-distinct-files gate) promotes nothing
// and never creates findings.json — that must score as "no findings", not crash the
// whole corpus run with ENOENT (the bug that killed cases 3–9 of the first full run).
const readFindings = (work) => readJsonIfPresent(storeFor(work).findingsPath)?.findings ?? [];

function nodeMatch(expected, filePath, startLine) {
  if (norm(filePath) !== norm(expected.filePath)) return false;
  if (startLine == null || expected.line == null) return true;
  return Math.abs(Number(startLine) - Number(expected.line)) <= LINE_TOL;
}

export function expectedContextInDeepScanPrep(expected, prep) {
  const files = new Set((prep.files ?? []).map((f) => norm(f.filePath)));
  const sites = [];
  for (const f of prep.files ?? []) {
    for (const o of f.obligations ?? []) sites.push({ filePath: f.filePath, line: o.line });
  }
  for (const o of prep.obligationOverlay?.obligations ?? []) sites.push({ filePath: o.filePath, line: o.line });
  for (const lead of prep.cpgLeads ?? []) {
    sites.push({ filePath: lead.filePath, line: lead.sinkLine });
    if (lead.sourceLine != null) sites.push({ filePath: lead.filePath, line: lead.sourceLine });
  }
  return {
    fileContext: expected.some((e) => files.has(norm(e.filePath))),
    siteContext: expected.some((e) => sites.some((s) => nodeMatch(e, s.filePath, s.line)))
  };
}

export function expectedContextInDeepHuntAnchors(expected, anchors) {
  return {
    fileContext: expected.some((e) => anchors.some((a) => norm(a.filePath) === norm(e.filePath))),
    siteContext: expected.some((e) => anchors.some((a) => nodeMatch(e, a.filePath, a.line)))
  };
}

// deep-scan finding: the anchor is evidence[0].
export function anchorMatch(expected, finding) {
  const ev = finding.evidence?.[0];
  return ev ? nodeMatch(expected, ev.filePath, ev.startLine) : false;
}

// deep-hunt finding: the vulnerable line can be the source, the sink, or any hop on
// the path — so a hit is ANY evidence anchor OR any evidenceGraph node matching an
// expected anchor. (A cross-file flow shouldn't be scored a miss just because the
// expected line is the sink, not evidence[0].)
export function findingHitsExpected(expected, finding) {
  for (const a of finding.evidence ?? []) if (nodeMatch(expected, a.filePath, a.startLine)) return true;
  for (const nd of finding.evidenceGraph?.nodes ?? []) if (nodeMatch(expected, nd.filePath, nd.startLine)) return true;
  return false;
}

function isProvenFinding(f) {
  if (["reviewed", "noise", "rejected", "remediated"].includes(String(f.status ?? ""))) return false;
  return f.status === "proven" || f.poc?.proofVerdict === "exploited";
}

export function falseProofStats(findings, safeExpectations, hitFn = anchorMatch) {
  const proven = (findings ?? []).filter(isProvenFinding);
  const falseProofs = (safeExpectations ?? []).filter((safe) => proven.some((f) => hitFn(safe, f))).length;
  return {
    provenTotal: proven.length,
    falseProofs,
    falseProofRate: proven.length ? falseProofs / proven.length : 0
  };
}

// Finalize CLIs call process.exit(1) on a malformed draft; stub it so a bad agent
// draft is recorded, not fatal to the harness.
function safe(fn) {
  const orig = process.exit;
  process.exit = (c) => { throw new Error(`exit(${c})`); };
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, error: String(e.message || e) }; }
  finally { process.exit = orig; }
}

function discover() {
  const dir = CVE_MODE ? CVES : CASES;
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(dir, d.name, "expected.json")))
    .filter((d) => existsSync(join(dir, d.name, "repo")))  // fetched / present
    .filter((d) => !ONLY || d.name === ONLY)
    .map((d) => ({ name: d.name, dir: join(dir, d.name) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function oneRun(caseDir, expected, safeExpectations = []) {
  // Blind scratch copy — no expected.json sibling reachable from the repo root.
  const work = mkdtempSync(join(tmpdir(), "kz-eval-"));
  cpSync(join(caseDir, "repo"), work, { recursive: true });
  mkdirSync(join(work, ".kuzushi"), { recursive: true });
  let cost = 0;
  const trace = {};

  // 1. deep-scan prepare (deterministic). --files forces a focused deep read of
  // specific files; otherwise rank the repo. The ranked list is also the routing check.
  const dprep = prepareDeepScan(work, FOCUS_FILES.length ? { files: FOCUS_FILES } : { maxFiles: MAX_FILES, cpgMemory: CPG_MEMORY });
  const prepDoc = JSON.parse(readFileSync(dprep.prepPath, "utf8"));
  const ctx = expectedContextInDeepScanPrep(expected, prepDoc);
  trace.routed = ctx.fileContext;
  trace.inContext = ctx.fileContext;
  trace.siteInContext = ctx.siteContext;
  const prepFiles = (prepDoc.files ?? []).map((f) => norm(f.filePath));

  // 2. deep-scanner agent(s). Default = one pass over all routed files. --batch N =
  // read them in small DEPTH batches across multiple agent passes (the proven lever:
  // few files read deeply beats many read shallowly), each batch finalized into the
  // lock-guarded index.
  const batches = (!FOCUS_FILES.length && BATCH > 0)
    ? Array.from({ length: Math.ceil(prepFiles.length / BATCH) }, (_, i) => prepFiles.slice(i * BATCH, i * BATCH + BATCH))
    : [null]; // null = use the single prep as-is
  trace.deepPasses = batches.length;
  let anyDraft = false;
  for (const batch of batches) {
    const bp = batch ? prepareDeepScan(work, { files: batch, buildCodeGraph: false }) : dprep;
    const dr = runAgent({
      agentMdPath: join(PLUGIN, "agents", "deep-scanner.md"),
      task: deepScanTask({ prepPath: bp.prepPath, repoDir: work, pluginDir: PLUGIN, draftPath: bp.draftPath }),
      repoDir: work, pluginDir: PLUGIN, draftPath: bp.draftPath, model: MODEL, timeoutMs: TIMEOUT_MS
    });
    cost += dr.cost;
    if (dr.draftWritten) { anyDraft = true; safe(() => finalizeDeepScan(work, bp.runDir)); }
  }
  if (!anyDraft) return { ...trace, cost, found: false, confirmed: false, note: "deep-agent wrote no draft", work };

  // score: did a deep-scan finding land on an expected anchor?
  let findings = readFindings(work);
  const matched = findings.filter((f) => f.source === "deep-scan" && expected.some((e) => anchorMatch(e, f)));
  trace.found = matched.length > 0;
  trace.deepFindingCount = findings.filter((f) => f.source === "deep-scan").length;

  // 4. verify (LLM) — only if there are open findings to verify
  if (findings.some((f) => f.status === "open")) {
    const vprep = prepareVerify(work, { maxCandidates: 12 });
    const vr = runAgent({
      agentMdPath: join(PLUGIN, "agents", "verifier.md"),
      task: verifyTask({ prepPath: vprep.prepPath, repoDir: work, pluginDir: PLUGIN, draftPath: vprep.draftPath }),
      repoDir: work, pluginDir: PLUGIN, draftPath: vprep.draftPath, model: MODEL, timeoutMs: TIMEOUT_MS
    });
    cost += vr.cost; trace.verifyAgent = { ok: vr.ok, cost: vr.cost, secs: Math.round(vr.elapsedMs / 1000) };
    if (vr.draftWritten) {
      const vfin = safe(() => assembleVerify(work, vprep.runDir));
      trace.verifyError = vfin.ok ? null : vfin.error;
      findings = readFindings(work);
    }
  }

  const confirmedMatched = findings.filter((f) => expected.some((e) => anchorMatch(e, f)) && f.verification?.verdict === "confirmed-exploitable");
  const provenMatched = findings.filter((f) => expected.some((e) => anchorMatch(e, f)) && f.status === "proven");
  const fpStats = falseProofStats(findings, safeExpectations, anchorMatch);
  trace.confirmed = confirmedMatched.length > 0;
  trace.proven = provenMatched.length > 0;
  trace.provenTotal = fpStats.provenTotal;
  trace.falseProofs = fpStats.falseProofs;
  trace.extraConfirmed = findings.filter((f) => f.verification?.verdict === "confirmed-exploitable" && !expected.some((e) => anchorMatch(e, f))).length;
  trace.extraProven = findings.filter((f) => f.status === "proven" && !expected.some((e) => anchorMatch(e, f))).length;
  trace.cost = cost;
  trace.work = work;
  return trace;
}

// The deep-hunt lane: anchor → the deep-hunter walks flows across files → finalize →
// (verify) → score. Distinct from oneRun (the whole-file deep reader) so the two recall
// lanes are measured separately and comparably. The extra signal here is `crossFile`:
// did the matched flow actually span ≥2 files — the thing deep-scan / same-file taint
// structurally can't produce.
function oneRunDeepHunt(caseDir, expected, safeExpectations = []) {
  const work = mkdtempSync(join(tmpdir(), "kz-eval-dh-"));
  cpSync(join(caseDir, "repo"), work, { recursive: true });
  mkdirSync(join(work, ".kuzushi"), { recursive: true });
  let cost = 0;
  const trace = { mode: "deep-hunt" };

  // 1. anchor (deterministic). The anchor set is the routing check.
  const hprep = prepareDeepHunt(work, { maxAnchors: MAX_ANCHORS, scopeDir: "." });
  const anchors = JSON.parse(readFileSync(hprep.prepPath, "utf8")).anchors ?? [];
  const ctx = expectedContextInDeepHuntAnchors(expected, anchors);
  trace.routed = ctx.fileContext;
  trace.inContext = ctx.fileContext;
  trace.siteInContext = ctx.siteContext;
  trace.anchorCount = anchors.length;
  trace.unanchored = hprep.unanchoredCount ?? 0;

  // 2. deep-hunter agent — the interprocedural walk.
  const dr = runAgent({
    agentMdPath: join(PLUGIN, "agents", "deep-hunter.md"),
    task: deepHuntTask({ prepPath: hprep.prepPath, repoDir: work, pluginDir: PLUGIN, draftPath: hprep.draftPath }),
    repoDir: work, pluginDir: PLUGIN, draftPath: hprep.draftPath, model: MODEL, timeoutMs: TIMEOUT_MS
  });
  cost += dr.cost;
  trace.huntAgent = { ok: dr.ok, cost: dr.cost, secs: Math.round(dr.elapsedMs / 1000) };
  if (!dr.draftWritten) return { ...trace, cost, found: false, confirmed: false, crossFile: false, note: "deep-hunt agent wrote no draft", work };
  safe(() => finalizeDeepHunt(work, hprep.runDir));

  // score: did a deep-hunt finding's path touch an expected anchor?
  let findings = readFindings(work);
  const dh = findings.filter((f) => f.source === "deep-hunt");
  const matched = dh.filter((f) => expected.some((e) => findingHitsExpected(e, f)));
  trace.found = matched.length > 0;
  trace.deepHuntFindingCount = dh.length;
  trace.crossFile = matched.some((f) => new Set((f.evidenceGraph?.nodes ?? []).map((n) => norm(n.filePath))).size >= 2);

  // 3. verify (LLM) — only if there are open findings.
  if (findings.some((f) => f.status === "open")) {
    const vprep = prepareVerify(work, { maxCandidates: 12 });
    const vr = runAgent({
      agentMdPath: join(PLUGIN, "agents", "verifier.md"),
      task: verifyTask({ prepPath: vprep.prepPath, repoDir: work, pluginDir: PLUGIN, draftPath: vprep.draftPath }),
      repoDir: work, pluginDir: PLUGIN, draftPath: vprep.draftPath, model: MODEL, timeoutMs: TIMEOUT_MS
    });
    cost += vr.cost; trace.verifyAgent = { ok: vr.ok, cost: vr.cost, secs: Math.round(vr.elapsedMs / 1000) };
    if (vr.draftWritten) { safe(() => assembleVerify(work, vprep.runDir)); findings = readFindings(work); }
  }

  const fpStats = falseProofStats(findings, safeExpectations, findingHitsExpected);
  trace.confirmed = findings.some((f) => expected.some((e) => findingHitsExpected(e, f)) && f.verification?.verdict === "confirmed-exploitable");
  trace.proven = findings.some((f) => expected.some((e) => findingHitsExpected(e, f)) && f.status === "proven");
  trace.provenTotal = fpStats.provenTotal;
  trace.falseProofs = fpStats.falseProofs;
  trace.extraConfirmed = findings.filter((f) => f.verification?.verdict === "confirmed-exploitable" && !expected.some((e) => findingHitsExpected(e, f))).length;
  trace.extraProven = findings.filter((f) => f.status === "proven" && !expected.some((e) => findingHitsExpected(e, f))).length;
  trace.cost = cost;
  trace.work = work;
  return trace;
}

// The discover lane: deterministic recon → the fuzz-discoverer builds+runs crafted inputs
// → finalize re-runs the draft bytes and the sanitizer report promotes proven findings →
// score. This is the routing-INDEPENDENT lane, so its headline metric is `proven` (a real
// sanitizer abort on the vulnerable file), not `found`/`confirmed` by reading. `routed` is
// kept only as an info signal: did the recon even surface the vulnerable file as a seed.
async function oneRunDiscover(caseDir, expected, safeExpectations = []) {
  const work = mkdtempSync(join(tmpdir(), "kz-eval-disc-"));
  cpSync(join(caseDir, "repo"), work, { recursive: true });
  mkdirSync(join(work, ".kuzushi"), { recursive: true });
  let cost = 0;
  const trace = { mode: "discover" };

  // 1. recon prep (deterministic). Self-skips honestly on a non-buildable target.
  const prep = prepareFuzzDiscover(work, {});
  trace.discoverStatus = prep.status;
  const subs = JSON.parse(readFileSync(prep.prepPath, "utf8")).subsystems ?? [];
  const seedFiles = new Set(subs.flatMap((s) => (s.files ?? []).map(norm)));
  trace.routed = expected.some((e) => seedFiles.has(norm(e.filePath)));
  trace.inContext = null;
  trace.siteInContext = null;
  if (prep.status !== "prepared") {
    return { ...trace, cost, found: false, confirmed: false, note: `discover skip: ${prep.status}`, work };
  }

  // 2. fuzz-discoverer agent — builds an ASan/UBSan target, crafts inputs, RUNS them.
  const dr = runAgent({
    agentMdPath: join(PLUGIN, "agents", "fuzz-discoverer.md"),
    task: fuzzDiscoverTask({ prepPath: prep.prepPath, repoDir: work, pluginDir: PLUGIN, draftPath: prep.draftPath }),
    repoDir: work, pluginDir: PLUGIN, draftPath: prep.draftPath, model: MODEL, timeoutMs: TIMEOUT_MS
  });
  cost += dr.cost; trace.discoverAgent = { ok: dr.ok, cost: dr.cost, secs: Math.round(dr.elapsedMs / 1000) };
  if (!dr.draftWritten) return { ...trace, cost, found: false, confirmed: false, note: "discoverer wrote no draft", work };

  // 3. finalize: re-run the draft bytes; the sanitizer report decides + promotes. Local
  // backend (no docker in CI), consented for the eval scratch copy.
  try { await finalizeFuzzDiscover(work, prep.runDir, { trustLocal: true, backend: "local" }); }
  catch (e) { trace.finalizeError = String(e.message || e); }

  const proven = readFindings(work).filter((f) => f.source === "fuzz-discover" && f.status === "proven");
  const onExpected = proven.filter((f) => expected.some((e) => anchorMatch(e, f) || findingHitsExpected(e, f)));
  const fpStats = falseProofStats(proven, safeExpectations, (e, f) => anchorMatch(e, f) || findingHitsExpected(e, f));
  trace.provenCount = proven.length;
  trace.found = onExpected.length > 0;       // for the discover lane, "found" == proven-on-target
  trace.confirmed = onExpected.length > 0;   // proven is strictly stronger than confirmed
  trace.proven = onExpected.length > 0;
  trace.provenTotal = fpStats.provenTotal;
  trace.falseProofs = fpStats.falseProofs;
  trace.extraConfirmed = proven.length - onExpected.length; // proven-but-off-target (FP proxy)
  trace.extraProven = trace.extraConfirmed;
  trace.cost = cost; trace.work = work;
  return trace;
}

export function pct(n, d) { return d ? `${Math.round((n / d) * 100)}%` : "n/a"; }
function ratio(n, d) { return d ? `${n}/${d}` : "n/a"; }

export function aggregateEvalRows(rows) {
  const agg = {
    routed: 0,
    found: 0,
    confirmed: 0,
    proven: 0,
    crossFile: 0,
    total: 0,
    contextTotal: 0,
    foundGivenContext: 0,
    siteContextEligible: 0,
    siteContextTotal: 0,
    foundGivenSiteContext: 0,
    extraConfirmed: 0,
    extraProven: 0,
    provenTotal: 0,
    falseProofs: 0,
    safeDecoyRuns: 0,
    cost: 0
  };
  for (const row of rows) {
    for (const r of row.runs ?? []) {
      agg.total += 1;
      if (r.routed) agg.routed += 1;
      if (r.found) agg.found += 1;
      if (r.confirmed) agg.confirmed += 1;
      if (r.proven) agg.proven += 1;
      if (r.crossFile) agg.crossFile += 1;
      if (r.inContext === true) {
        agg.contextTotal += 1;
        if (r.found) agg.foundGivenContext += 1;
      }
      if (r.siteInContext !== null && r.siteInContext !== undefined) {
        agg.siteContextEligible += 1;
        if (r.siteInContext === true) {
          agg.siteContextTotal += 1;
          if (r.found) agg.foundGivenSiteContext += 1;
        }
      }
      agg.extraConfirmed += Number(r.extraConfirmed ?? 0);
      agg.extraProven += Number(r.extraProven ?? 0);
      agg.provenTotal += Number(r.provenTotal ?? 0);
      agg.falseProofs += Number(r.falseProofs ?? 0);
      if (r.safeDecoyCount) agg.safeDecoyRuns += 1;
      agg.cost += Number(r.cost ?? 0);
    }
  }
  return {
    ...agg,
    routingRecall: agg.total ? agg.routed / agg.total : null,
    reasoningRecall: agg.contextTotal ? agg.foundGivenContext / agg.contextTotal : null,
    siteContextRecall: agg.siteContextEligible ? agg.siteContextTotal / agg.siteContextEligible : null,
    siteReasoningRecall: agg.siteContextTotal ? agg.foundGivenSiteContext / agg.siteContextTotal : null,
    blindRecall: agg.total ? agg.found / agg.total : null,
    confirmedOnTarget: agg.total ? agg.confirmed / agg.total : null,
    provenOnTarget: agg.total ? agg.proven / agg.total : null,
    extraConfirmedPerCase: agg.total ? agg.extraConfirmed / agg.total : null,
    extraProvenPerCase: agg.total ? agg.extraProven / agg.total : null,
    falseProofRate: agg.provenTotal ? agg.falseProofs / agg.provenTotal : 0,
    costPerTrueFinding: agg.found ? agg.cost / agg.found : null
  };
}

function serializableRows(rows) {
  return rows.map((row) => ({
    name: row.name,
    expectedFile: row.expectedFile,
    runs: row.runs.map(({ work, ...r }) => r)
  }));
}

async function main() {
  if (spawnSync("claude", ["--version"], { encoding: "utf8" }).status !== 0) {
    console.error("eval: `claude` CLI not found on PATH — the harness needs it to run the real agents."); process.exit(1);
  }
  const cases = discover();
  if (!cases.length) {
    console.error(`eval: no ${CVE_MODE ? "fetched CVE" : "synthetic"} cases. ${CVE_MODE ? "Run bench/cves/<id>/fetch.sh first." : ""}`);
    process.exit(CVE_MODE ? 2 : 1);
  }

  const rows = [];
  let totalCost = 0;
  for (const c of cases) {
    const groundTruth = JSON.parse(readFileSync(join(c.dir, "expected.json"), "utf8"));
    const expected = expectedVulnerabilities(groundTruth);
    const safeExpectations = expectedSafeDecoys(groundTruth);
    const runs = [];
    for (let r = 0; r < REPS; r++) {
      process.stderr.write(`▶ ${c.name} (run ${r + 1}/${REPS}, model=${MODEL}, lane=${MODE})…\n`);
      const runner = MODE === "deep-hunt" ? oneRunDeepHunt : MODE === "discover" ? oneRunDiscover : oneRun;
      const res = await runner(c.dir, expected, safeExpectations);
      res.safeDecoyCount = safeExpectations.length;
      totalCost += res.cost || 0;
      runs.push(res);
      process.stderr.write(`  routed=${res.routed} found=${res.found} confirmed=${res.confirmed} cost=$${(res.cost || 0).toFixed(2)}${res.note ? " — " + res.note : ""}\n`);
    }
    rows.push({ name: c.name, expectedFile: expected[0]?.filePath, safeDecoyCount: safeExpectations.length, runs });
  }

  // Scoreboard
  const dh = MODE === "deep-hunt";
  const L = [];
  L.push(`# kuzushi LLM-in-the-loop eval — ${MODE} lane — ${CVE_MODE ? "real CVEs" : "synthetic"}`);
  L.push("");
  L.push(`Model: **${MODEL}** · lane: **${MODE}** · reps/case: **${REPS}** · cases: **${rows.length}** · ${dh ? `maxAnchors: ${MAX_ANCHORS}` : `maxFiles: ${MAX_FILES}`} · timeout: **${Math.round(TIMEOUT_MS / 60000)}m/agent** · total cost: **$${totalCost.toFixed(2)}**`);
  L.push("");
  const disc = MODE === "discover";
  L.push(`These numbers are the REAL agents (${disc ? "fuzz-discoverer" : dh ? "deep-hunter" : "deep-scanner"}${disc ? "" : " + verifier"}) run blind via \`claude -p\`,`);
  L.push("not human-authored drafts. Small-N and nondeterministic — directional, not a leaderboard.");
  if (disc) {
    L.push("`routed` = the recon surfaced the vulnerable file as a seed (info only — this lane is");
    L.push("routing-INDEPENDENT); `found`/`confirmed` = a fuzz-discover finding reached **proven** on");
    L.push("the vulnerable file by a real sanitizer abort (the headline metric); `extra` = proven");
    L.push("findings off the expected anchor (a false-positive proxy / bonus bug).");
  } else if (dh) {
    L.push("`routed` = a trace anchor landed in the vulnerable file; `found` = a deep-hunt finding's");
    L.push("path touched it (±6 lines); `cross-file` = that flow spanned ≥2 files (the deep-hunt");
    L.push("value-add same-file taint can't produce); `confirmed` = the verifier called it exploitable.");
  } else {
    L.push("`routed` = the deep reader's prep put the vulnerable file in the read set; `found` = a");
    L.push("deep-scan finding landed on it (±6 lines); `confirmed` = the verifier called it exploitable.");
  }
  L.push("");
  L.push(`| Case | expected file | routed | in-context | site-context | found | reasoning-hit | site-hit | confirmed | proven | false-proofs |${dh ? " cross-file |" : ""} extra-confirmed | extra-proven |`);
  L.push(`|---|---|---|---|---|---|---|---|---|---|---|${dh ? "---|" : ""}---|---|`);
  for (const row of rows) {
    const n = row.runs.length;
    const routed = row.runs.filter((r) => r.routed).length;
    const contextRuns = row.runs.filter((r) => r.inContext === true).length;
    const hasContextMetric = row.runs.some((r) => r.inContext !== null);
    const foundGivenContext = row.runs.filter((r) => r.inContext === true && r.found).length;
    const siteRuns = row.runs.filter((r) => r.siteInContext === true).length;
    const hasSiteMetric = row.runs.some((r) => r.siteInContext !== null && r.siteInContext !== undefined);
    const foundGivenSite = row.runs.filter((r) => r.siteInContext === true && r.found).length;
    const found = row.runs.filter((r) => r.found).length;
    const conf = row.runs.filter((r) => r.confirmed).length;
    const proven = row.runs.filter((r) => r.proven).length;
    const falseProofs = row.runs.reduce((a, r) => a + Number(r.falseProofs ?? 0), 0);
    const xf = row.runs.filter((r) => r.crossFile).length;
    const fp = (row.runs.reduce((a, r) => a + (r.extraConfirmed || 0), 0) / n).toFixed(1);
    const xproof = (row.runs.reduce((a, r) => a + (r.extraProven || 0), 0) / n).toFixed(1);
    L.push(`| ${row.name} | \`${row.expectedFile}\` | ${routed}/${n} | ${hasContextMetric ? `${contextRuns}/${n}` : "n/a"} | ${hasSiteMetric ? `${siteRuns}/${n}` : "n/a"} | ${found}/${n} | ${hasContextMetric ? ratio(foundGivenContext, contextRuns) : "n/a"} | ${hasSiteMetric ? ratio(foundGivenSite, siteRuns) : "n/a"} | ${conf}/${n} | ${proven}/${n} | ${falseProofs} |${dh ? ` ${xf}/${n} |` : ""} ${fp} | ${xproof} |`);
  }
  const agg = aggregateEvalRows(rows);
  L.push(`| **overall** | | **${pct(agg.routed, agg.total)}** | **${agg.contextTotal ? pct(agg.contextTotal, agg.total) : "n/a"}** | **${agg.siteContextEligible ? pct(agg.siteContextTotal, agg.siteContextEligible) : "n/a"}** | **${pct(agg.found, agg.total)}** | **${pct(agg.foundGivenContext, agg.contextTotal)}** | **${pct(agg.foundGivenSiteContext, agg.siteContextTotal)}** | **${pct(agg.confirmed, agg.total)}** | **${pct(agg.proven, agg.total)}** | **${agg.falseProofs}** |${dh ? ` **${pct(agg.crossFile, agg.total)}** |` : ""} **${agg.extraConfirmedPerCase == null ? "n/a" : agg.extraConfirmedPerCase.toFixed(2)}** | **${agg.extraProvenPerCase == null ? "n/a" : agg.extraProvenPerCase.toFixed(2)}** |`);
  L.push("");
  L.push("## Aggregate metrics");
  L.push("");
  L.push(`- Routing recall: **${pct(agg.routed, agg.total)}** (${agg.routed}/${agg.total})`);
  L.push(`- Reasoning recall given context: **${pct(agg.foundGivenContext, agg.contextTotal)}** (${ratio(agg.foundGivenContext, agg.contextTotal)})`);
  L.push(`- Site-context recall: **${pct(agg.siteContextTotal, agg.siteContextEligible)}** (${ratio(agg.siteContextTotal, agg.siteContextEligible)})`);
  L.push(`- Site-context reasoning recall: **${pct(agg.foundGivenSiteContext, agg.siteContextTotal)}** (${ratio(agg.foundGivenSiteContext, agg.siteContextTotal)})`);
  L.push(`- End-to-end blind recall: **${pct(agg.found, agg.total)}** (${agg.found}/${agg.total})`);
  L.push(`- Confirmed on target: **${pct(agg.confirmed, agg.total)}** (${agg.confirmed}/${agg.total})`);
  L.push(`- Proven on target: **${pct(agg.proven, agg.total)}** (${agg.proven}/${agg.total})`);
  L.push(`- False-proof rate: **${pct(agg.falseProofs, agg.provenTotal)}** (${agg.falseProofs}/${agg.provenTotal})`);
  L.push(`- Extra-confirmed per case: **${agg.extraConfirmedPerCase == null ? "n/a" : agg.extraConfirmedPerCase.toFixed(2)}**`);
  L.push(`- Extra-proven per case: **${agg.extraProvenPerCase == null ? "n/a" : agg.extraProvenPerCase.toFixed(2)}**`);
  L.push(`- Cost per true finding: **${agg.costPerTrueFinding == null ? "n/a" : `$${agg.costPerTrueFinding.toFixed(2)}`}**`);
  L.push("");
  const out = `${L.join("\n")}\n`;
  const base = disc ? "scoreboard.discover" : dh ? "scoreboard.deep-hunt" : "scoreboard";
  writeFileSync(join(HERE, `${base}${CVE_MODE ? ".cve" : ""}.md`), out);
  writeFileSync(join(HERE, `${base}${CVE_MODE ? ".cve" : ""}.json`), `${JSON.stringify({
    schemaVersion: "eval-scoreboard.v2",
    generatedAt: new Date().toISOString(),
    model: MODEL,
    mode: MODE,
    cve: CVE_MODE,
    reps: REPS,
    cases: rows.length,
    timeoutMs: TIMEOUT_MS,
    aggregate: agg,
    rows: serializableRows(rows)
  }, null, 2)}\n`);
  process.stdout.write(out);
  process.stderr.write(`\nDONE — routed ${pct(agg.routed, agg.total)} · reasoning ${pct(agg.foundGivenContext, agg.contextTotal)} · found ${pct(agg.found, agg.total)} · confirmed ${pct(agg.confirmed, agg.total)} · proven ${pct(agg.proven, agg.total)}${dh ? ` · cross-file ${pct(agg.crossFile, agg.total)}` : ""} · $${totalCost.toFixed(2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => { console.error(e); process.exit(1); });
