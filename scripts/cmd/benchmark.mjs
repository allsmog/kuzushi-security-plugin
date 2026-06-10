#!/usr/bin/env node
// /benchmark — measure recall / precision / false-proof against a ground-truth
// manifest. Two modes:
//   --case <name>            score a bundled corpus case using its recorded
//                            findings.json (reproducible regression in CI).
//   --target <path>          score a live run's <target>/.kuzushi/findings.json
//     --ground-truth <file>  against the given ground-truth manifest.
//
// The scorer (scripts/lib/bench-score.mjs) is pure; this is just I/O + reporting.
// Aggregating over the whole corpus gives the single number BENCHMARKS.md asks
// for: are we missing bugs, crying wolf, or — worst — proving non-bugs?

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult } from "../lib/artifact-store.mjs";
import { scoreFindings } from "../lib/bench-score.mjs";

const CASES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "bench", "cases");

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fail(message) {
  console.error(`benchmark: ${message}`);
  process.exit(1);
}

// Score one case directory: needs expected.json (ground truth) + findings.json
// (the recorded or live run output).
function scoreCase(caseDir, opts) {
  const expectedPath = join(caseDir, "expected.json");
  const findingsPath = join(caseDir, "findings.json");
  if (!existsSync(expectedPath)) fail(`case ${caseDir} has no expected.json`);
  if (!existsSync(findingsPath)) fail(`case ${caseDir} has no findings.json (record a run first)`);
  const score = scoreFindings(readJson(expectedPath), readJson(findingsPath), opts);
  return { case: caseDir.split("/").pop(), ...score };
}

function listCases() {
  if (!existsSync(CASES_DIR)) return [];
  return readdirSync(CASES_DIR).filter((n) => statSync(join(CASES_DIR, n)).isDirectory());
}

// Aggregate per-case metrics into a corpus-wide line.
function aggregate(cases) {
  const sum = (k) => cases.reduce((a, c) => a + (c[k] ?? 0), 0);
  const tp = sum("truePositives"), fn = sum("falseNegatives"), fp = sum("falsePositives"), proven = sum("provenCount"), fpr = sum("falseProofs");
  const ratio = (n, d) => (d === 0 ? null : Number((n / d).toFixed(4)));
  return {
    cases: cases.length,
    truePositives: tp, falseNegatives: fn, falsePositives: fp, falseProofs: fpr, provenCount: proven,
    recall: ratio(tp, tp + fn),
    precision: ratio(tp, tp + fp),
    falseProofRate: ratio(fpr, proven)
  };
}

export function runBenchmark(options = {}) {
  const opts = { lineTolerance: options.lineTolerance, matchCwe: options.matchCwe, strict: options.strict };
  let cases;
  if (options.target) {
    const gtPath = options.groundTruth;
    if (!gtPath) fail("--target requires --ground-truth <manifest.json>");
    const findingsPath = join(resolve(options.target), ".kuzushi", "findings.json");
    if (!existsSync(findingsPath)) fail(`no findings.json under ${options.target}/.kuzushi — run the pipeline first`);
    const score = scoreFindings(readJson(resolve(gtPath)), readJson(findingsPath), opts);
    cases = [{ case: resolve(options.target), ...score }];
  } else {
    const names = options.case ? [options.case] : listCases();
    if (!names.length) fail(`no benchmark cases found under ${CASES_DIR}`);
    cases = names.map((n) => scoreCase(join(CASES_DIR, n), opts));
  }
  return { ok: true, status: "completed", corpus: aggregate(cases), cases };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("benchmark [--case <name>] [--target <path> --ground-truth <file>] [--strict] [--line-tolerance 5] [--no-match-cwe]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["help", "strict", "no-match-cwe"],
    value: ["case", "target", "ground-truth", "line-tolerance"]
  });
  const result = runBenchmark({
    case: flags.case,
    target: flags.target,
    groundTruth: flags["ground-truth"],
    strict: Boolean(flags.strict),
    matchCwe: !flags["no-match-cwe"],
    lineTolerance: flags["line-tolerance"] ? Number(flags["line-tolerance"]) : undefined
  });
  emitResult(result);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
