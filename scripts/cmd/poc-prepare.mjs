#!/usr/bin/env node
// Prepare phase for /poc (empirical proof). Selects the findings /verify marked
// PoC-ready (verification.verdict ∈ {confirmed-exploitable, inconclusive}),
// detects the language of each by file extension, carries through the
// verification pocSketch + a source excerpt, allocates a per-finding harness
// directory under the run dir, and probes the sandbox backend (docker / local /
// none). The agent then writes a harness into each harnessDir; poc-assemble runs
// it deterministically. No baked-in exploit logic — the agent writes the harness.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join, extname } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { detectBackend } from "../lib/sandbox.mjs";

const EXCERPT_RADIUS = 10;

const EXT_LANGUAGE = {
  ".rs": "rust",
  ".py": "python",
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
  ".ts": "typescript", ".tsx": "typescript",
  ".c": "c", ".h": "c",
  ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".go": "go",
  ".java": "java"
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

export function preparePoc(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — run /verify first`);
  }
  const pocReady = (findingsDoc.findings ?? []).filter((f) => f.verification?.pocReady);
  if (!pocReady.length) {
    throw new Error("no PoC-ready findings — run /verify first (need confirmed-exploitable or inconclusive verdicts)");
  }
  const maxCandidates = Number(input.maxCandidates ?? 8);
  const sandbox = detectBackend();

  const run = openRun(resolvedTarget, "poc");
  const candidates = pocReady.slice(0, maxCandidates).map((f) => {
    const anchor = (f.evidence ?? [])[0];
    return {
      findingFingerprint: f.fingerprint,
      title: f.title,
      cwe: f.cwe,
      source: f.source,
      language: languageFor(anchor?.filePath),
      evidence: f.evidence ?? [],
      excerpt: excerptFor(resolvedTarget, anchor),
      verification: f.verification ?? null,
      harnessDir: join(run.runDir, "poc", f.fingerprint)
    };
  });

  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    sandbox,
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
    draftPath: join(run.runDir, "draft.poc.json"),
    candidateCount: candidates.length,
    sandbox,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "poc-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("poc-prepare --target <path> [--input '{\"maxCandidates\":8}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("poc-prepare: --target is required");
    process.exit(1);
  }
  emitResult(preparePoc(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
