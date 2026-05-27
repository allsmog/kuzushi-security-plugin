#!/usr/bin/env node
// Prepare phase for /fix (patch generation + PoC⁺ validation). Selects findings
// worth fixing (proven / confirmed / open-exploitable), preferring those with a
// /poc harness so the patch can be empirically validated. Per finding it gathers
// a wide source excerpt, the verification pocSketch + exploitability context, the
// matching poc.json entry (harnessDir / runCommand / language), the target files,
// and the full current contents of each target file (so the agent can write a
// correct unified diff). Probes the sandbox backend. No baked-in fix logic — the
// agent root-causes and writes the diff. Read-only (writes only the run prep).

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join, extname } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { detectBackend } from "../lib/sandbox.mjs";
import { oracleSummaryForFinding } from "../lib/oracles.mjs";

const EXCERPT_RADIUS = 25; // wider than verify/poc — a patch needs surrounding context
const MAX_FILE_BYTES_DEFAULT = 200_000;

const EXT_LANGUAGE = {
  ".rs": "rust", ".py": "python",
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
  ".ts": "typescript", ".tsx": "typescript",
  ".c": "c", ".h": "c",
  ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".go": "go", ".java": "java"
};

function languageFor(filePath) {
  return EXT_LANGUAGE[extname(filePath ?? "").toLowerCase()] ?? "unknown";
}

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - EXCERPT_RADIUS);
  const end = Math.min(lines.length, anchorLine + EXCERPT_RADIUS);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

// Findings worth fixing: confirmed-exploitable (confirmed by /verify) or proven
// by /poc. Exclude open static-only findings so /fix cannot skip the proof
// ladder.
function isCandidate(finding) {
  if (finding.status === "patched" || finding.status === "remediated") return false;
  if (finding.fix) return false;
  return finding.status === "proven" || finding.status === "confirmed";
}

export function prepareFix(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — run /verify (and /poc) first`);
  }
  const maxCandidates = Number(input.maxCandidates ?? 8);
  const maxFileBytes = Number(input.maxFileBytes ?? MAX_FILE_BYTES_DEFAULT);

  // Index the poc.json results by fingerprint so each candidate can carry its
  // existing harness (the thing the patch must defeat).
  const pocDoc = readJsonIfPresent(store.pocPath);
  const pocByFp = new Map((pocDoc?.results ?? []).map((r) => [r.findingFingerprint, r]));

  const all = (findingsDoc.findings ?? []).filter(isCandidate);
  if (!all.length) {
    throw new Error("no fixable findings — run /verify first (and /poc when possible); /fix requires confirmed or proven findings");
  }
  // Prefer findings that have a poc harness (so validation can actually run).
  const ordered = all.sort((a, b) => (pocByFp.has(b.fingerprint) ? 1 : 0) - (pocByFp.has(a.fingerprint) ? 1 : 0));

  const run = openRun(resolvedTarget, "fix");
  const candidates = ordered.slice(0, maxCandidates).map((f) => {
    const anchor = (f.evidence ?? [])[0];
    const poc = pocByFp.get(f.fingerprint) ?? null;
    // Distinct target files across the evidence anchors (the diff's allowed scope).
    const targetFiles = [...new Set((f.evidence ?? []).map((e) => e.filePath).filter(Boolean))];
    const fileContents = {};
    for (const rel of targetFiles) {
      const abs = resolve(resolvedTarget, rel);
      if (!existsSync(abs) || statSync(abs).isDirectory()) continue;
      const text = readFileSync(abs, "utf8");
      if (Buffer.byteLength(text, "utf8") > maxFileBytes) {
        fileContents[rel] = { tooLarge: true, bytes: Buffer.byteLength(text, "utf8") };
      } else {
        fileContents[rel] = text;
      }
    }
    return {
      findingFingerprint: f.fingerprint,
      source: f.source,
      refId: f.refId,
      title: f.title,
      severity: f.severity,
      cwe: f.cwe,
      verdict: f.verdict,
      status: f.status,
      rationale: f.rationale,
      language: languageFor(anchor?.filePath),
      evidence: f.evidence ?? [],
      excerpt: excerptFor(resolvedTarget, anchor),
      verification: f.verification ?? null,
      exploitability: f.exploitability ?? null,
      semanticOracle: oracleSummaryForFinding(f),
      targetFiles,
      fileContents,
      hasHarness: Boolean(poc),
      poc: poc ? {
        harnessDir: poc.harnessDir,
        runCommand: poc.runCommand,
        language: poc.language ?? languageFor(anchor?.filePath),
        expectedSignal: poc.expectedSignal ?? "crash",
        proofVerdict: poc.proofVerdict
      } : null
    };
  });

  const sandbox = detectBackend();
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    findingsMtime: statSync(store.findingsPath).mtime.toISOString(),
    sandbox,
    pocPresent: Boolean(pocDoc),
    candidates,
    input
  });

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.fix.json"),
    candidateCount: candidates.length,
    withHarness: candidates.filter((c) => c.hasHarness).length,
    sandbox,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "fix-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fix-prepare --target <path> [--input '{\"maxCandidates\":8}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("fix-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareFix(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
