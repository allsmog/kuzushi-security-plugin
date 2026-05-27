#!/usr/bin/env node
// Initialize a fuzzing campaign plan from confirmed/proven findings. This does
// not claim execution evidence; it creates a deterministic, reviewable harness
// workspace and per-finding engine recommendation that /fuzz-run can execute
// once a harness runCommand is present.

import { existsSync, mkdirSync, statSync, readFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { oracleSummaryForFinding } from "../lib/oracles.mjs";

const MEMORY_CWES = new Set(["119","120","121","122","124","125","126","127","131","190","191","415","416","476","787","824"]);
const EXT_LANGUAGE = {
  ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".java": "java", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust"
};

function cweNumber(cwe) {
  return String(Array.isArray(cwe) ? cwe[0] : (cwe ?? "")).replace(/^CWE-/i, "").trim();
}

function languageFor(filePath) {
  return EXT_LANGUAGE[extname(filePath ?? "").toLowerCase()] ?? "unknown";
}

function engineFor(language, cwe) {
  if (language === "c" || language === "cpp") return "libfuzzer";
  if (language === "java") return "jazzer";
  if (language === "javascript" || language === "typescript") return "node-property";
  if (language === "go") return "go-fuzz";
  if (language === "rust") return "cargo-fuzz";
  if (MEMORY_CWES.has(cweNumber(cwe))) return "libfuzzer";
  return "custom";
}

function defaultCommand(engine) {
  return {
    libfuzzer: "./fuzz_target -max_total_time=60 corpus",
    jazzer: "jazzer --cp target/classes --target_class FuzzTarget",
    "node-property": "npm test -- --runInBand fuzz",
    "go-fuzz": "go test ./... -run=^$ -fuzz=. -fuzztime=60s",
    "cargo-fuzz": "cargo fuzz run fuzz_target -- -max_total_time=60",
    custom: null
  }[engine] ?? null;
}

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - 15);
  const end = Math.min(lines.length, anchorLine + 15);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

function seedable(finding) {
  return finding.status === "confirmed" || finding.status === "proven";
}

export function fuzzInit(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — run /verify first`);

  const maxSeeds = Number(input.maxSeeds ?? 8);
  const seeds = (findingsDoc.findings ?? []).filter(seedable).slice(0, maxSeeds);
  mkdirSync(store.fuzzDir, { recursive: true });
  const run = openRun(resolvedTarget, "fuzz-init");
  const harnessRoot = join(store.fuzzDir, "harnesses");
  mkdirSync(harnessRoot, { recursive: true });

  const candidates = seeds.map((finding) => {
    const anchor = (finding.evidence ?? [])[0] ?? {};
    const language = languageFor(anchor.filePath);
    const engine = engineFor(language, finding.cwe);
    const harnessDir = join(harnessRoot, finding.fingerprint);
    mkdirSync(harnessDir, { recursive: true });
    return {
      findingFingerprint: finding.fingerprint,
      title: finding.title,
      cwe: finding.cwe,
      severity: finding.severity,
      status: finding.status,
      evidence: finding.evidence ?? [],
      excerpt: excerptFor(resolvedTarget, anchor),
      language,
      engine,
      harnessDir,
      runCommand: input.runCommand ?? defaultCommand(engine),
      corpusDir: join(harnessDir, "corpus"),
      timeoutMs: Number(input.timeoutMs ?? 120000),
      semanticOracle: oracleSummaryForFinding(finding),
      notes: "Review or replace runCommand after writing a real fuzz harness into harnessDir; /fuzz-run only executes candidates with an existing harnessDir and runCommand."
    };
  });

  const doc = {
    version: "1.0",
    schemaVersion: "fuzz-plan.v1",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    runId: run.runId,
    candidates,
    summary: { seedCount: seeds.length, candidateCount: candidates.length }
  };
  atomicWrite(store.fuzzPlanPath, `${JSON.stringify(doc, null, 2)}\n`);
  run.writeJson("fuzz-plan.json", doc);
  const result = {
    ok: true,
    status: candidates.length ? "prepared" : "no-seeds",
    target: resolvedTarget,
    runId: run.runId,
    fuzzPlanPath: store.fuzzPlanPath,
    candidateCount: candidates.length,
    next: candidates.length ? "write or review harnesses, then run /fuzz-run" : "run /verify first; fuzzing requires confirmed/proven seeds"
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-init --target <path> [--input '{\"maxSeeds\":8,\"timeoutMs\":120000}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("fuzz-init: --target is required");
    process.exit(1);
  }
  emitResult(fuzzInit(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
