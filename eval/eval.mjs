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
import { prepareVerify } from "../scripts/cmd/verify-prepare.mjs";
import { assembleVerify } from "../scripts/cmd/verify-assemble.mjs";
import { runAgent, deepScanTask, verifyTask } from "./run-agent.mjs";

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
const ONLY = opt("--case", null);
const FOCUS_FILES = (opt("--files", "") || "").split(",").map((s) => s.trim()).filter(Boolean);
const BATCH = Number(opt("--batch", "0"));  // >0: deep-read the routed files in small batches (depth), multi-pass
const CVE_MODE = args.includes("--cve");

const norm = (p) => String(p ?? "").replace(/^\.\//, "");
function anchorMatch(expected, finding) {
  const ev = finding.evidence?.[0];
  if (!ev) return false;
  if (norm(ev.filePath) !== norm(expected.filePath)) return false;
  if (ev.startLine == null || expected.line == null) return true;
  return Math.abs(Number(ev.startLine) - Number(expected.line)) <= LINE_TOL;
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
      repoDir: work, pluginDir: PLUGIN, draftPath: bp.draftPath, model: MODEL
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
      repoDir: work, pluginDir: PLUGIN, draftPath: vprep.draftPath, model: MODEL
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
      process.stderr.write(`▶ ${c.name} (run ${r + 1}/${REPS}, model=${MODEL})…\n`);
      const res = oneRun(c.dir, expected);
      totalCost += res.cost || 0;
      runs.push(res);
      process.stderr.write(`  routed=${res.routed} found=${res.found} confirmed=${res.confirmed} cost=$${(res.cost || 0).toFixed(2)}${res.note ? " — " + res.note : ""}\n`);
    }
    rows.push({ name: c.name, expectedFile: expected[0]?.filePath, runs });
  }

  // Scoreboard
  const L = [];
  L.push(`# kuzushi LLM-in-the-loop eval — ${CVE_MODE ? "real CVEs" : "synthetic"}`);
  L.push("");
  L.push(`Model: **${MODEL}** · reps/case: **${REPS}** · cases: **${rows.length}** · deep-scan maxFiles: ${MAX_FILES} · total cost: **$${totalCost.toFixed(2)}**`);
  L.push("");
  L.push("These numbers are the REAL agents (deep-scanner + verifier) run blind via `claude -p`,");
  L.push("not human-authored drafts. Small-N and nondeterministic — directional, not a leaderboard.");
  L.push("`routed` = the deep reader's prep put the vulnerable file in the read set; `found` = a");
  L.push("deep-scan finding landed on it (±6 lines); `confirmed` = the verifier called it exploitable.");
  L.push("");
  L.push("| Case | expected file | routed | found | confirmed | extra-confirmed (FP proxy) |");
  L.push("|---|---|---|---|---|---|");
  const agg = { routed: 0, found: 0, confirmed: 0, total: 0 };
  for (const row of rows) {
    const n = row.runs.length;
    const routed = row.runs.filter((r) => r.routed).length;
    const found = row.runs.filter((r) => r.found).length;
    const conf = row.runs.filter((r) => r.confirmed).length;
    const fp = (row.runs.reduce((a, r) => a + (r.extraConfirmed || 0), 0) / n).toFixed(1);
    agg.routed += routed; agg.found += found; agg.confirmed += conf; agg.total += n;
    L.push(`| ${row.name} | \`${row.expectedFile}\` | ${routed}/${n} | ${found}/${n} | ${conf}/${n} | ${fp} |`);
  }
  L.push(`| **overall** | | **${pct(agg.routed, agg.total)}** | **${pct(agg.found, agg.total)}** | **${pct(agg.confirmed, agg.total)}** | |`);
  L.push("");
  const out = `${L.join("\n")}\n`;
  writeFileSync(join(HERE, CVE_MODE ? "scoreboard.cve.md" : "scoreboard.md"), out);
  process.stdout.write(out);
  process.stderr.write(`\nDONE — routed ${pct(agg.routed, agg.total)} · found ${pct(agg.found, agg.total)} · confirmed ${pct(agg.confirmed, agg.total)} · $${totalCost.toFixed(2)}\n`);
}

main();
