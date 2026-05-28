#!/usr/bin/env node
// kuzushi benchmark harness.
//
// "Better than Xint" is unfalsifiable until it's measured. This harness makes the
// claim a number — without needing an LLM in the loop, so it runs in CI.
//
// It measures CANDIDATE RECALL: the deterministic prepare phase of every producer
// is a pattern scanner, and a vulnerability a producer never even surfaces as a
// candidate can never be reported. So "did /sweep route some producer to every
// known-vulnerable site?" is a real, reproducible precursor to end-to-end recall —
// and it's exactly the whole-repo-coverage gap /sweep was built to close.
//
// For each case it computes recall two ways and reports the lift:
//   • baseline: a single producer (taint-analysis) run once, whole repo, default caps
//   • sweep:    the full /sweep plan — every applicable producer × every shard
//
// Full end-to-end recall (with the agents reasoning + verifying) is the manual path
// documented in bench/README.md; this is the CI-able floor.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync, writeFileSync, cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { prepareSweep } from "../scripts/cmd/sweep-prepare.mjs";
import { prepareTaintAnalysis } from "../scripts/cmd/taint-analysis-prepare.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CASES_DIR = join(HERE, "cases");
const LINE_TOLERANCE = 6;
const SWEEP_FLOOR = 0.6; // overall sweep recall must clear this for `npm run bench` to pass

function norm(p) {
  return String(p ?? "").replace(/^\.\//, "");
}

// Recursively harvest every (filePath, line?) anchor from a prep.json-shaped
// object — robust to each producer's candidate shape (authz/crypto/logic carry
// {filePath,line}; threat-hunt carries excerpt.filePath; taint carries
// candidateFiles string arrays). We also treat bare path strings under a
// `candidateFiles`/`files` key as file-level anchors.
function harvest(node, out) {
  if (node == null) return;
  if (Array.isArray(node)) {
    for (const x of node) harvest(x, out);
    return;
  }
  if (typeof node !== "object") return;
  if (typeof node.filePath === "string") {
    const line = Number(node.line ?? node.startLine);
    out.push({ filePath: norm(node.filePath), line: Number.isFinite(line) ? line : null });
  }
  for (const [key, val] of Object.entries(node)) {
    if ((key === "candidateFiles" || key === "files" || key === "sinks" || key === "sources") && Array.isArray(val)) {
      for (const f of val) if (typeof f === "string") out.push({ filePath: norm(f), line: null });
    }
    harvest(val, out);
  }
}

function anchorsHit(expected, harvested) {
  return expected.filter((e) =>
    harvested.some((h) =>
      h.filePath === norm(e.filePath) &&
      (h.line == null || e.line == null || Math.abs(h.line - e.line) <= LINE_TOLERANCE)
    )
  ).length;
}

// Run one producer prepareCommand (from the plan), read its prep.json, harvest.
function harvestFromCommand(prepareCommand) {
  const r = spawnSync(prepareCommand, { shell: true, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const out = [];
  if (r.status !== 0 && !r.stdout) return out;
  let envelope;
  try { envelope = JSON.parse(r.stdout); } catch { return out; }
  const prepPath = envelope?.prepPath;
  if (!prepPath || !existsSync(prepPath)) return out;
  try { harvest(JSON.parse(readFileSync(prepPath, "utf8")), out); } catch { /* ignore */ }
  return out;
}

function runCase(caseDir) {
  const name = caseDir;
  const root = join(CASES_DIR, caseDir);
  const expected = JSON.parse(readFileSync(join(root, "expected.json"), "utf8")).expected ?? [];
  // Copy the case repo to a temp dir so producer runs don't write .kuzushi/
  // artifacts into the committed cases/ tree.
  const repo = mkdtempSync(join(tmpdir(), `kz-bench-${caseDir}-`));
  cpSync(join(root, "repo"), repo, { recursive: true });

  // Baseline: a single producer, whole repo, default caps.
  const baseHarvest = [];
  try {
    const prep = prepareTaintAnalysis(repo, {});
    if (prep.prepPath && existsSync(prep.prepPath)) harvest(JSON.parse(readFileSync(prep.prepPath, "utf8")), baseHarvest);
  } catch { /* baseline best-effort */ }
  const baseHits = anchorsHit(expected, baseHarvest);

  // Sweep: every applicable producer × every shard.
  const plan = prepareSweep(repo, {});
  const planDoc = JSON.parse(readFileSync(storeFor(repo).sweepPlanPath, "utf8"));
  const sweepHarvest = [];
  for (const job of planDoc.jobs) {
    sweepHarvest.push(...harvestFromCommand(job.prepareCommand));
  }
  const sweepHits = anchorsHit(expected, sweepHarvest);

  return {
    name,
    expected: expected.length,
    baselineHits: baseHits,
    baselineRecall: expected.length ? baseHits / expected.length : 1,
    sweepHits,
    sweepRecall: expected.length ? sweepHits / expected.length : 1,
    shardCount: plan.shardCount,
    jobCount: plan.jobCount
  };
}

function pct(x) {
  return `${Math.round(x * 1000) / 10}%`;
}

function main() {
  if (!existsSync(CASES_DIR)) {
    console.error(`no cases dir at ${CASES_DIR}`);
    process.exit(1);
  }
  const cases = readdirSync(CASES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(CASES_DIR, d.name, "expected.json")))
    .map((d) => d.name)
    .sort();

  if (!cases.length) {
    console.error("no benchmark cases found");
    process.exit(1);
  }

  const results = cases.map(runCase);
  const totExpected = results.reduce((n, r) => n + r.expected, 0);
  const totSweep = results.reduce((n, r) => n + r.sweepHits, 0);
  const totBase = results.reduce((n, r) => n + r.baselineHits, 0);
  const overallSweep = totExpected ? totSweep / totExpected : 1;
  const overallBase = totExpected ? totBase / totExpected : 1;

  // Scoreboard.
  const lines = [];
  lines.push("# kuzushi benchmark scoreboard");
  lines.push("");
  lines.push("Candidate recall — fraction of known-vulnerable sites a producer's deterministic");
  lines.push("prepare phase surfaces as a candidate (the precursor to end-to-end recall). Higher is");
  lines.push("better; `/sweep` should dominate a single-producer baseline by routing every applicable");
  lines.push("producer across every shard. See methodology in this directory's README.");
  lines.push("");
  lines.push("| Case | Expected | Baseline (taint only) | /sweep | Lift |");
  lines.push("|---|---|---|---|---|");
  for (const r of results) {
    lines.push(`| ${r.name} | ${r.expected} | ${r.baselineHits}/${r.expected} (${pct(r.baselineRecall)}) | ${r.sweepHits}/${r.expected} (${pct(r.sweepRecall)}) | +${pct(r.sweepRecall - r.baselineRecall)} |`);
  }
  lines.push(`| **overall** | **${totExpected}** | **${pct(overallBase)}** | **${pct(overallSweep)}** | **+${pct(overallSweep - overallBase)}** |`);
  lines.push("");
  lines.push(`_Generated by \`npm run bench\`. Floor for pass: overall /sweep recall ≥ ${pct(SWEEP_FLOOR)}._`);
  lines.push("");
  const scoreboard = `${lines.join("\n")}`;
  writeFileSync(join(HERE, "scoreboard.md"), scoreboard);
  process.stdout.write(`${scoreboard}\n`);

  // Gate: sweep must clear the floor AND never do worse than the baseline.
  let ok = overallSweep >= SWEEP_FLOOR;
  for (const r of results) {
    if (r.sweepRecall < r.baselineRecall) {
      console.error(`REGRESSION: ${r.name} sweep recall ${pct(r.sweepRecall)} < baseline ${pct(r.baselineRecall)}`);
      ok = false;
    }
  }
  if (!ok) {
    console.error(`\nbench FAILED (overall sweep recall ${pct(overallSweep)}; floor ${pct(SWEEP_FLOOR)})`);
    process.exit(1);
  }
  console.error(`\nbench PASSED — overall /sweep recall ${pct(overallSweep)} vs baseline ${pct(overallBase)}`);
}

main();

export { harvest, anchorsHit, runCase, resolve };
