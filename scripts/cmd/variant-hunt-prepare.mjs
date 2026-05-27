#!/usr/bin/env node
// Prepare phase for /variant-hunt (find siblings of confirmed bugs).
//
// Reads the shared findings index, picks the CONFIRMED bugs as "seeds"
// (status confirmed/proven, or a still-open threat-hunt/systems-hunt
// "exploitable"/taint "finding"), and for each seed builds:
//   - a source excerpt around its primary evidence anchor (the bug to generalize),
//   - a broad initial candidate-file set found by ripgrep'ing the seed's CWE
//     structural queries (from the typed taint catalog) across the repo.
// The variant-hunter agent then does the narrow→general search and triage.
// No baked-in verdicts here — deterministic seeding only. Read-only.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs } from "../lib/ripgrep.mjs";
import { loadCatalog, normalizeCweId } from "../lib/taint-catalog.mjs";

const EXCERPT_RADIUS = 10;

// A finding worth finding siblings of: something a producer or verifier already
// stands behind. Proven/confirmed are strongest; an open exploitable/finding is
// a reasonable seed too. Skip reviewed / noise / needs-evidence.
function isSeed(f) {
  if (f.status === "confirmed" || f.status === "proven") return true;
  if (f.status === "open" && (f.verdict === "exploitable" || f.verdict === "finding")) return true;
  return false;
}

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

// Catalog entry for the seed's CWE → the structural tokens worth ripgrepping
// repo-wide for an initial broad candidate set (the agent narrows from there).
function catalogFor(cwe) {
  if (!cwe) return null;
  const want = normalizeCweId(cwe);
  return loadCatalog().find((e) => normalizeCweId(e.cwe) === want) ?? null;
}

// Broad first pass: ripgrep the seed's structural queries (≥3 chars, fixed
// string) and return ranked candidate files (excluding the seed's own file).
function candidateFilesFor(target, entry, seedFile, maxFiles = 40) {
  if (!entry) return [];
  const patterns = [...new Set([...(entry.structuralQueries ?? []), ...(entry.sinkSignals ?? [])])]
    .filter((p) => typeof p === "string" && p.length >= 3)
    .slice(0, 60);
  if (!patterns.length) return [];
  const globs = buildGlobs();
  const seen = new Map();
  for (const pattern of patterns) {
    const result = runRg(target, ["--json", "-n", "-S", "--max-count", "3", "-F", "-e", pattern, ...globs, "."]);
    if (!result.ok) continue;
    for (const hit of parseJsonMatches(result.stdout, 200)) {
      if (!hit.filePath || hit.filePath === seedFile) continue;
      const score = rankHit(hit, "generic");
      const prev = seen.get(hit.filePath);
      if (!prev || score > prev.score) seen.set(hit.filePath, { filePath: hit.filePath, line: hit.line, text: hit.text, score });
    }
  }
  return [...seen.values()].sort((a, b) => b.score - a.score).slice(0, maxFiles).map(({ score, ...rest }) => rest);
}

export function prepareVariantHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — run /threat-hunt, /taint-analysis or /systems-hunt (then /verify) first`);
  }
  const maxSeeds = Number(input.maxSeeds ?? 8);
  const seeds = (findingsDoc.findings ?? []).filter(isSeed).slice(0, maxSeeds).map((f) => {
    const cwe = Array.isArray(f.cwe) ? f.cwe[0] : f.cwe;
    const entry = catalogFor(cwe);
    const anchor = f.evidence?.[0];
    return {
      seedFingerprint: f.fingerprint,
      title: f.title,
      cwe: cwe ?? "",
      taintClass: entry?.taintClass ?? "",
      severity: f.severity ?? "",
      source: f.source,
      anchor: anchor ? { filePath: anchor.filePath, startLine: anchor.startLine } : null,
      excerpt: excerptFor(resolvedTarget, anchor),
      signals: entry ? { sinkSignals: entry.sinkSignals ?? [], structuralQueries: entry.structuralQueries ?? [] } : null,
      candidateFiles: catalogFor(cwe) ? candidateFilesFor(resolvedTarget, entry, anchor?.filePath) : []
    };
  });

  const run = openRun(resolvedTarget, "variant-hunt");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    references: artifactSnapshot(resolvedTarget),
    seedCount: seeds.length,
    seeds,
    input
  });

  return {
    ok: true,
    status: seeds.length ? "prepared" : "no-seeds",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.variant-hunt.json"),
    seedCount: seeds.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "variant-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("variant-hunt-prepare --target <path> [--input '{\"maxSeeds\":8}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("variant-hunt-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareVariantHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
