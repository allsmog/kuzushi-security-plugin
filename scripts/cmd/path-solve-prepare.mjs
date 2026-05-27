#!/usr/bin/env node
// Prepare phase for /path-solve (concolic-lite path-constraint solving). Selects
// hard-to-reach findings — the ones /verify left `inconclusive` / needs-trace —
// and gathers the source + sink anchors, wide excerpts, matched threat-intel, and
// the code-graph call-path context, so the path-solver agent can extract the guard
// predicate between source and sink and solve it (LLM, or the concolic backend).
// Read-only, deterministic.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

const EXCERPT_RADIUS = 14;

function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path)) return { filePath: anchor.filePath, startLine: anchor.startLine ?? 1, missing: true, lines: [] };
  if (statSync(path).isDirectory()) return { filePath: anchor.filePath, startLine: 1, isDirectory: true, lines: [] };
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  const start = Math.max(1, anchorLine - EXCERPT_RADIUS);
  const end = Math.min(lines.length, anchorLine + EXCERPT_RADIUS);
  return { filePath: anchor.filePath, startLine: anchorLine, lines: lines.slice(start - 1, end).map((text, i) => ({ line: start + i, text })) };
}

// threat-intel CVE leads + invariants matched by CWE (seed known bypass/payloads).
function intelFor(finding, intel) {
  if (!intel || !finding.cwe) return null;
  const cwe = String(Array.isArray(finding.cwe) ? finding.cwe[0] : finding.cwe);
  const leads = [...(intel.cves?.stack ?? []), ...(intel.cves?.similarApps ?? [])].filter((l) => String(l.cwe) === cwe);
  const invariants = (intel.invariants ?? []).filter((i) => String(i.cwe) === cwe);
  return leads.length || invariants.length ? { leads, invariants } : null;
}

// Code-graph symbols defined in the source/sink files + their caller counts — a
// hint about the functions on the path whose guards matter. Null when no graph.
function graphContextFor(codeGraph, files) {
  if (!codeGraph?.symbols) return null;
  const want = new Set(files.map((f) => String(f).replace(/^\.\//, "")));
  const syms = codeGraph.symbols
    .filter((s) => want.has(String(s.file ?? "").replace(/^\.\//, "")))
    .map((s) => ({ name: s.name, file: s.file, line: s.line, callerCount: s.callerCount }));
  return syms.length ? syms.slice(0, 40) : null;
}

// Hard-to-reach findings worth solving a path for: /verify said inconclusive, or a
// producer asked for an active trace. (Explicit fingerprints override the filter.)
function isCandidate(finding) {
  if (finding.verification?.verdict === "inconclusive") return true;
  if (finding.status === "needs-trace") return true;
  if (finding.verdict === "needs-active-agent-trace") return true;
  return false;
}

export function preparePathSolve(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — run a producer + /verify first`);
  }
  const intel = readJsonIfPresent(store.threatIntelPath);
  const codeGraph = readJsonIfPresent(store.codeGraphPath);
  const maxCandidates = Number(input.maxCandidates ?? 8);
  const wanted = Array.isArray(input.fingerprints) ? new Set(input.fingerprints) : null;

  const candidates = (findingsDoc.findings ?? [])
    .filter((f) => (wanted ? wanted.has(f.fingerprint) : isCandidate(f)))
    .slice(0, maxCandidates)
    .map((f) => {
      const anchors = (f.evidence ?? []).filter((a) => a?.filePath);
      const sourceAnchor = anchors[0] ?? null;
      const sinkAnchor = anchors.length > 1 ? anchors[anchors.length - 1] : anchors[0] ?? null;
      const files = [...new Set(anchors.map((a) => a.filePath))];
      return {
        findingFingerprint: f.fingerprint,
        title: f.title,
        cwe: f.cwe,
        severity: f.severity,
        status: f.status,
        verdict: f.verdict,
        verification: f.verification ?? null,
        sourceAnchor,
        sinkAnchor,
        sourceExcerpt: excerptFor(resolvedTarget, sourceAnchor),
        sinkExcerpt: sinkAnchor && sinkAnchor !== sourceAnchor ? excerptFor(resolvedTarget, sinkAnchor) : null,
        intel: intelFor(f, intel),
        graphContext: graphContextFor(codeGraph, files)
      };
    });

  const run = openRun(resolvedTarget, "path-solve");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    codeGraphPresent: Boolean(codeGraph), candidateCount: candidates.length, candidates, input
  });

  return {
    ok: true,
    status: candidates.length ? "prepared" : "no-candidates",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.path-solve.json"),
    candidateCount: candidates.length,
    codeGraphPresent: Boolean(codeGraph),
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "path-solve-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("path-solve-prepare --target <path> [--input '{\"fingerprints\":[\"…\"],\"maxCandidates\":8}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("path-solve-prepare: --target is required");
    process.exit(1);
  }
  emitResult(preparePathSolve(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
