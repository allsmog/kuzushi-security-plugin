#!/usr/bin/env node
// kuzushi benchmark harness.
//
// "Better than Xint on raw bug-finding power" is unfalsifiable until it's measured.
// This makes it a number — without an LLM in the loop, so it runs in CI.
//
// It measures CANDIDATE RECALL: a producer's deterministic prepare phase decides
// which sites get looked at at all; a vuln no producer surfaces can never be
// reported. So "did kuzushi route attention to every known-vulnerable site?" is a
// sound, reproducible precursor to end-to-end recall. Three lanes per case:
//   • baseline  — one pattern producer (taint-analysis), whole repo
//   • pattern   — full /sweep, pattern producers only
//   • deep      — full /sweep --deep (adds the whole-file reader /deep-scan)
// The headline is deep − pattern: the recall the un-pattern-gated reader adds,
// especially on bugs no regex matches (custom wrappers, cross-file flows).
//
// `--cve` runs the same lanes against real projects cloned at a vulnerable commit
// (bench/cves/<id>/, fetched on demand) — the credible "as good as Xint" evidence.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync, writeFileSync, cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { prepareSweep } from "../scripts/cmd/sweep-prepare.mjs";
import { prepareTaintAnalysis } from "../scripts/cmd/taint-analysis-prepare.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CASES_DIR = join(HERE, "cases");
const CVES_DIR = join(HERE, "cves");
const LINE_TOLERANCE = 6;
const DEEP_FLOOR = 0.8; // overall deep recall must clear this for `npm run bench` to pass

function norm(p) {
  return String(p ?? "").replace(/^\.\//, "");
}

// Recursively harvest every (filePath, line?) anchor from a prep.json-shaped object
// — robust to each producer's shape (pattern producers carry {filePath,line};
// deep-scan carries files:[{filePath}]; taint carries candidateFiles string arrays).
function harvest(node, out) {
  if (node == null) return;
  if (Array.isArray(node)) { for (const x of node) harvest(x, out); return; }
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

function harvestFromCommand(prepareCommand) {
  const r = spawnSync(prepareCommand, { shell: true, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const out = [];
  if (r.status !== 0 && !r.stdout) return out;
  let envelope;
  try { envelope = JSON.parse(r.stdout); } catch { return out; }
  if (!envelope?.prepPath || !existsSync(envelope.prepPath)) return out;
  try { harvest(JSON.parse(readFileSync(envelope.prepPath, "utf8")), out); } catch { /* ignore */ }
  return out;
}

// Run a /sweep plan (optionally deep) and harvest every job's prep anchors.
function sweepHarvest(repo, opts) {
  prepareSweep(repo, opts);
  const planDoc = JSON.parse(readFileSync(storeFor(repo).sweepPlanPath, "utf8"));
  const out = [];
  for (const job of planDoc.jobs) out.push(...harvestFromCommand(job.prepareCommand));
  return out;
}

function runCase(root, name) {
  const expected = JSON.parse(readFileSync(join(root, "expected.json"), "utf8")).expected ?? [];
  const repo = mkdtempSync(join(tmpdir(), `kz-bench-${name}-`));
  cpSync(join(root, "repo"), repo, { recursive: true });

  // Lane 1: single-producer baseline.
  const base = [];
  try {
    const prep = prepareTaintAnalysis(repo, {});
    if (prep.prepPath && existsSync(prep.prepPath)) harvest(JSON.parse(readFileSync(prep.prepPath, "utf8")), base);
  } catch { /* best-effort */ }

  // Lane 2: pattern sweep. Lane 3: deep sweep (adds /deep-scan).
  const pattern = sweepHarvest(repo, {});
  const deep = sweepHarvest(repo, { deep: true });

  const n = expected.length || 1;
  return {
    name,
    expected: expected.length,
    baselineRecall: anchorsHit(expected, base) / n,
    patternRecall: anchorsHit(expected, pattern) / n,
    deepRecall: anchorsHit(expected, deep) / n
  };
}

function pct(x) { return `${Math.round(x * 1000) / 10}%`; }

function discoverCases(dir, requireRepo) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(dir, d.name, "expected.json")))
    .filter((d) => !requireRepo || existsSync(join(dir, d.name, "repo")))
    .map((d) => d.name)
    .sort();
}

function scoreboard(title, results, floorNote) {
  const tot = results.reduce((a, r) => a + r.expected, 0) || 1;
  const sum = (k) => results.reduce((a, r) => a + r[k] * r.expected, 0) / tot;
  const lines = [`# ${title}`, "",
    "Candidate recall — fraction of known-vulnerable sites a producer's deterministic prepare",
    "phase surfaces (the precursor to end-to-end recall). `deep` adds the whole-file reader",
    "`/deep-scan`; its lift over `pattern` is the bugs no regex matches.", "",
    "| Case | Expected | baseline | pattern /sweep | deep /sweep | deep lift |",
    "|---|---|---|---|---|---|"];
  for (const r of results) {
    lines.push(`| ${r.name} | ${r.expected} | ${pct(r.baselineRecall)} | ${pct(r.patternRecall)} | ${pct(r.deepRecall)} | +${pct(r.deepRecall - r.patternRecall)} |`);
  }
  lines.push(`| **overall** | **${results.reduce((a, r) => a + r.expected, 0)}** | **${pct(sum("baselineRecall"))}** | **${pct(sum("patternRecall"))}** | **${pct(sum("deepRecall"))}** | **+${pct(sum("deepRecall") - sum("patternRecall"))}** |`);
  if (floorNote) { lines.push("", `_${floorNote}_`); }
  lines.push("");
  return { text: lines.join("\n"), overallDeep: sum("deepRecall"), overallPattern: sum("patternRecall") };
}

function main() {
  const cveMode = process.argv.includes("--cve");

  if (cveMode) {
    const names = discoverCases(CVES_DIR, true);
    const declared = discoverCases(CVES_DIR, false);
    if (!declared.length) { console.error(`no CVE cases declared under ${CVES_DIR}`); process.exit(1); }
    if (!names.length) {
      console.error(`No CVE case is fetched. Run the fetch.sh in a bench/cves/<id>/ dir first:`);
      for (const d of declared) console.error(`  bash ${join(CVES_DIR, d, "fetch.sh")}`);
      console.error("(Real-CVE cases clone real projects on demand; nothing is committed.)");
      process.exit(2);
    }
    const results = names.map((n) => runCase(join(CVES_DIR, n), n));
    const sb = scoreboard("kuzushi CVE benchmark scoreboard", results, `${names.length}/${declared.length} CVE cases fetched. Run other fetch.sh scripts for more.`);
    writeFileSync(join(HERE, "scoreboard.cve.md"), sb.text);
    process.stdout.write(`${sb.text}\n`);
    console.error(`\nCVE bench: deep recall ${pct(sb.overallDeep)} vs pattern ${pct(sb.overallPattern)} over ${names.length} fetched case(s).`);
    return;
  }

  const cases = discoverCases(CASES_DIR, false);
  if (!cases.length) { console.error("no benchmark cases found"); process.exit(1); }
  const results = cases.map((n) => runCase(join(CASES_DIR, n), n));
  const sb = scoreboard("kuzushi benchmark scoreboard", results, `Generated by \`npm run bench\`. Floor for pass: overall deep recall ≥ ${pct(DEEP_FLOOR)}.`);
  writeFileSync(join(HERE, "scoreboard.md"), sb.text);
  process.stdout.write(`${sb.text}\n`);

  let ok = sb.overallDeep >= DEEP_FLOOR;
  for (const r of results) {
    if (r.deepRecall < r.patternRecall) {
      console.error(`REGRESSION: ${r.name} deep recall ${pct(r.deepRecall)} < pattern ${pct(r.patternRecall)}`);
      ok = false;
    }
  }
  if (!ok) { console.error(`\nbench FAILED (overall deep recall ${pct(sb.overallDeep)}; floor ${pct(DEEP_FLOOR)})`); process.exit(1); }
  console.error(`\nbench PASSED — deep recall ${pct(sb.overallDeep)} vs pattern ${pct(sb.overallPattern)} vs baseline.`);
}

main();

export { harvest, anchorsHit, runCase };
