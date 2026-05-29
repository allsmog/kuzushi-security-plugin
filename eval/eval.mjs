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
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { prepareDeepScan } from "../scripts/cmd/deep-scan-prepare.mjs";
import { finalizeDeepScan } from "../scripts/cmd/deep-scan-finalize.mjs";
import { prepareDeepHunt } from "../scripts/cmd/deep-hunt-prepare.mjs";
import { finalizeDeepHunt } from "../scripts/cmd/deep-hunt-finalize.mjs";
import { prepareVerify } from "../scripts/cmd/verify-prepare.mjs";
import { assembleVerify } from "../scripts/cmd/verify-assemble.mjs";
import { runAgent, deepScanTask, deepHuntTask, verifyTask } from "./run-agent.mjs";

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

export const norm = (p) => String(p ?? "").replace(/^\.\//, "");

function nodeMatch(expected, filePath, startLine) {
  if (norm(filePath) !== norm(expected.filePath)) return false;
  if (startLine == null || expected.line == null) return true;
  return Math.abs(Number(startLine) - Number(expected.line)) <= LINE_TOL;
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

function oneRun(caseDir, expected) {
  // Blind scratch copy — no expected.json sibling reachable from the repo root.
  const work = mkdtempSync(join(tmpdir(), "kz-eval-"));
  cpSync(join(caseDir, "repo"), work, { recursive: true });
  mkdirSync(join(work, ".kuzushi"), { recursive: true });
  let cost = 0;
  const trace = {};

  // 1. deep-scan prepare (deterministic). --files forces a focused deep read of
  // specific files; otherwise rank the repo. The ranked list is also the routing check.
  const dprep = prepareDeepScan(work, FOCUS_FILES.length ? { files: FOCUS_FILES } : { maxFiles: MAX_FILES });
  const prepFiles = (JSON.parse(readFileSync(dprep.prepPath, "utf8")).files ?? []).map((f) => norm(f.filePath));
  trace.routed = expected.some((e) => prepFiles.includes(norm(e.filePath)));

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
  let findings = JSON.parse(readFileSync(storeFor(work).findingsPath, "utf8")).findings ?? [];
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
      findings = JSON.parse(readFileSync(storeFor(work).findingsPath, "utf8")).findings ?? [];
    }
  }

  const confirmedMatched = findings.filter((f) => expected.some((e) => anchorMatch(e, f)) && f.verification?.verdict === "confirmed-exploitable");
  trace.confirmed = confirmedMatched.length > 0;
  trace.extraConfirmed = findings.filter((f) => f.verification?.verdict === "confirmed-exploitable" && !expected.some((e) => anchorMatch(e, f))).length;
  trace.cost = cost;
  trace.work = work;
  return trace;
}

// The deep-hunt lane: anchor → the deep-hunter walks flows across files → finalize →
// (verify) → score. Distinct from oneRun (the whole-file deep reader) so the two recall
// lanes are measured separately and comparably. The extra signal here is `crossFile`:
// did the matched flow actually span ≥2 files — the thing deep-scan / same-file taint
// structurally can't produce.
function oneRunDeepHunt(caseDir, expected) {
  const work = mkdtempSync(join(tmpdir(), "kz-eval-dh-"));
  cpSync(join(caseDir, "repo"), work, { recursive: true });
  mkdirSync(join(work, ".kuzushi"), { recursive: true });
  let cost = 0;
  const trace = { mode: "deep-hunt" };

  // 1. anchor (deterministic). The anchor set is the routing check.
  const hprep = prepareDeepHunt(work, { maxAnchors: MAX_ANCHORS, scopeDir: "." });
  const anchors = JSON.parse(readFileSync(hprep.prepPath, "utf8")).anchors ?? [];
  trace.routed = expected.some((e) => anchors.some((a) => norm(a.filePath) === norm(e.filePath)));
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
  let findings = JSON.parse(readFileSync(storeFor(work).findingsPath, "utf8")).findings ?? [];
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
    if (vr.draftWritten) { safe(() => assembleVerify(work, vprep.runDir)); findings = JSON.parse(readFileSync(storeFor(work).findingsPath, "utf8")).findings ?? []; }
  }

  trace.confirmed = findings.some((f) => expected.some((e) => findingHitsExpected(e, f)) && f.verification?.verdict === "confirmed-exploitable");
  trace.extraConfirmed = findings.filter((f) => f.verification?.verdict === "confirmed-exploitable" && !expected.some((e) => findingHitsExpected(e, f))).length;
  trace.cost = cost;
  trace.work = work;
  return trace;
}

function pct(n, d) { return d ? `${Math.round((n / d) * 100)}%` : "n/a"; }

function main() {
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
    const expected = JSON.parse(readFileSync(join(c.dir, "expected.json"), "utf8")).expected ?? [];
    const runs = [];
    for (let r = 0; r < REPS; r++) {
      process.stderr.write(`▶ ${c.name} (run ${r + 1}/${REPS}, model=${MODEL}, lane=${MODE})…\n`);
      const res = (MODE === "deep-hunt" ? oneRunDeepHunt : oneRun)(c.dir, expected);
      totalCost += res.cost || 0;
      runs.push(res);
      process.stderr.write(`  routed=${res.routed} found=${res.found} confirmed=${res.confirmed} cost=$${(res.cost || 0).toFixed(2)}${res.note ? " — " + res.note : ""}\n`);
    }
    rows.push({ name: c.name, expectedFile: expected[0]?.filePath, runs });
  }

  // Scoreboard
  const dh = MODE === "deep-hunt";
  const L = [];
  L.push(`# kuzushi LLM-in-the-loop eval — ${MODE} lane — ${CVE_MODE ? "real CVEs" : "synthetic"}`);
  L.push("");
  L.push(`Model: **${MODEL}** · lane: **${MODE}** · reps/case: **${REPS}** · cases: **${rows.length}** · ${dh ? `maxAnchors: ${MAX_ANCHORS}` : `maxFiles: ${MAX_FILES}`} · timeout: **${Math.round(TIMEOUT_MS / 60000)}m/agent** · total cost: **$${totalCost.toFixed(2)}**`);
  L.push("");
  L.push(`These numbers are the REAL agents (${dh ? "deep-hunter" : "deep-scanner"} + verifier) run blind via \`claude -p\`,`);
  L.push("not human-authored drafts. Small-N and nondeterministic — directional, not a leaderboard.");
  if (dh) {
    L.push("`routed` = a trace anchor landed in the vulnerable file; `found` = a deep-hunt finding's");
    L.push("path touched it (±6 lines); `cross-file` = that flow spanned ≥2 files (the deep-hunt");
    L.push("value-add same-file taint can't produce); `confirmed` = the verifier called it exploitable.");
  } else {
    L.push("`routed` = the deep reader's prep put the vulnerable file in the read set; `found` = a");
    L.push("deep-scan finding landed on it (±6 lines); `confirmed` = the verifier called it exploitable.");
  }
  L.push("");
  L.push(`| Case | expected file | routed | found | confirmed |${dh ? " cross-file |" : ""} extra-confirmed (FP proxy) |`);
  L.push(`|---|---|---|---|---|${dh ? "---|" : ""}---|`);
  const agg = { routed: 0, found: 0, confirmed: 0, crossFile: 0, total: 0 };
  for (const row of rows) {
    const n = row.runs.length;
    const routed = row.runs.filter((r) => r.routed).length;
    const found = row.runs.filter((r) => r.found).length;
    const conf = row.runs.filter((r) => r.confirmed).length;
    const xf = row.runs.filter((r) => r.crossFile).length;
    const fp = (row.runs.reduce((a, r) => a + (r.extraConfirmed || 0), 0) / n).toFixed(1);
    agg.routed += routed; agg.found += found; agg.confirmed += conf; agg.crossFile += xf; agg.total += n;
    L.push(`| ${row.name} | \`${row.expectedFile}\` | ${routed}/${n} | ${found}/${n} | ${conf}/${n} |${dh ? ` ${xf}/${n} |` : ""} ${fp} |`);
  }
  L.push(`| **overall** | | **${pct(agg.routed, agg.total)}** | **${pct(agg.found, agg.total)}** | **${pct(agg.confirmed, agg.total)}** |${dh ? ` **${pct(agg.crossFile, agg.total)}** |` : ""} |`);
  L.push("");
  const out = `${L.join("\n")}\n`;
  const base = dh ? "scoreboard.deep-hunt" : "scoreboard";
  writeFileSync(join(HERE, `${base}${CVE_MODE ? ".cve" : ""}.md`), out);
  process.stdout.write(out);
  process.stderr.write(`\nDONE — routed ${pct(agg.routed, agg.total)} · found ${pct(agg.found, agg.total)} · confirmed ${pct(agg.confirmed, agg.total)}${dh ? ` · cross-file ${pct(agg.crossFile, agg.total)}` : ""} · $${totalCost.toFixed(2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
