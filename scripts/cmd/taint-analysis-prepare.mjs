#!/usr/bin/env node
// Prepare phase for /taint-analysis (IRIS-style source→sink taint hunt).
//
// Deterministic prepass — no LLM. Detects languages from the latest context
// run (falls back to file-extension inference), ranks the typed CWE catalog
// for this repo, seeds structural queries, ripgreps candidate files for the
// grep-able sink/source tokens, and reports which heavy backends (CodeQL DB,
// Joern CPG) are already built. Writes prep.json; the coordinator skill then
// spawns the labeler/tracer/triager subagents off these stage paths.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { hasContextRun, hasCodeqlDb, hasJoernCpg } from "../lib/context-status.mjs";
import { rankCatalog, buildStructuralQueries, languagesFromDisplayNames } from "../lib/taint-catalog.mjs";
import { listFiles, runRg } from "../lib/ripgrep.mjs";
import { componentOf } from "../lib/partition.mjs";

// Scope a candidate-file list to one partition's subsystem (for parallel fan-out:
// each per-partition hunter sees only its component's files). Resolves the
// partition by id or label against .kuzushi/partitions.json. Returns the filtered
// files + a note; a no-op (with a warning) when the partition can't be resolved.
function scopeToPartition(store, partitionRef, sinks, sources) {
  const doc = readJsonIfPresent(join(store.root, "partitions.json"));
  const part = (doc?.partitions ?? []).find((p) => p.id === partitionRef || p.label === partitionRef);
  if (!part) {
    return { sinks, sources, partition: null, warning: `partition "${partitionRef}" not found in .kuzushi/partitions.json — run /partition first; proceeding unscoped` };
  }
  const inPart = (f) => componentOf(f) === part.label;
  return { sinks: sinks.filter(inPart), sources: sources.filter(inPart), partition: { id: part.id, label: part.label }, warning: null };
}

const DEFAULTS = { maxCatalogEntries: 20, maxCandidateFiles: 80, maxPatternsForSearch: 120 };

// Extension → catalog language token, for fallback language inference when no
// context run exists yet.
const EXT_TO_LANG = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".rb": "ruby", ".erb": "ruby",
  ".php": "php", ".java": "java", ".kt": "kotlin", ".go": "go", ".rs": "rust",
  ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".scala": "scala"
};

// Read inventory.byLanguage from the most recent host-context-*/context.json.
function contextLanguages(store) {
  if (!existsSync(store.runsDir)) return null;
  let latest = null;
  for (const entry of readdirSync(store.runsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
    const ctx = join(store.runsDir, entry.name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtime;
    if (!latest || mtime > latest.mtime) latest = { ctx, mtime };
  }
  if (!latest) return null;
  const doc = readJsonIfPresent(latest.ctx);
  const byLanguage = doc?.inventory?.byLanguage ?? {};
  return { languages: languagesFromDisplayNames(byLanguage), raw: doc?.inventory ?? null };
}

// Fallback: infer languages by sampling source-file extensions.
function inferLanguages(target) {
  const counts = {};
  for (const file of listFiles(target).slice(0, 4000)) {
    const dot = file.lastIndexOf(".");
    if (dot === -1) continue;
    const lang = EXT_TO_LANG[file.slice(dot)];
    if (lang) counts[lang] = (counts[lang] ?? 0) + 1;
  }
  return Object.entries(counts).filter(([, n]) => n > 0).map(([l]) => l);
}

// ripgrep the grep-able structural patterns (fixed strings) and return the set
// of candidate files, capped. Patterns longer/codey enough to narrow the repo.
function candidateFiles(target, patterns, cap) {
  const usable = [...new Set(patterns)].filter((p) => p && p.length >= 3).slice(0, DEFAULTS.maxPatternsForSearch);
  if (!usable.length) return [];
  const args = ["-l", "-F", "--no-messages"];
  for (const p of usable) args.push("-e", p);
  args.push(".");
  const result = runRg(target, args);
  if (!result.ok) return [];
  return result.stdout.split(/\r?\n/).map((s) => s.replace(/^\.\//, "")).filter(Boolean).slice(0, cap);
}

export function prepareTaintAnalysis(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxCatalogEntries = Number(input.maxCatalogEntries ?? DEFAULTS.maxCatalogEntries);
  const maxCandidateFiles = Number(input.maxCandidateFiles ?? DEFAULTS.maxCandidateFiles);
  const minEvidenceLevel = input.minEvidenceLevel ?? "linked"; // candidate < linked < path

  const ctxState = hasContextRun(resolvedTarget);
  const ctxLangs = contextLanguages(store);
  const languages = ctxLangs?.languages?.length ? ctxLangs.languages : inferLanguages(resolvedTarget);
  const threatModel = readJsonIfPresent(store.threatModelPath);
  // /threat-intel CVEs for this stack are empirical evidence a bug class is live —
  // feed them into ranking so taint-analysis hunts those CWEs first.
  const threatIntel = readJsonIfPresent(store.threatIntelPath);

  const context = ctxLangs?.raw ? { languages, ...ctxLangs.raw } : { languages };
  const ranked = rankCatalog({ context, threatModel, threatIntel, languages }).slice(0, maxCatalogEntries);
  const structuralQueries = buildStructuralQueries(ranked);

  // Candidate files: sink/source-bearing tokens narrow where labelers look.
  const sinkPatterns = ranked.flatMap((e) => [...e.sinkSignals, ...e.structuralQueries]);
  const sourcePatterns = ranked.flatMap((e) => e.structuralQueries);
  let sinkCandidateFiles = candidateFiles(resolvedTarget, sinkPatterns, maxCandidateFiles);
  let sourceCandidateFiles = candidateFiles(resolvedTarget, sourcePatterns, maxCandidateFiles);

  // Parallel fan-out: when a partition is requested, scope this hunter to that
  // subsystem's files so concurrent partition runs cover different components.
  let partition = null;
  let partitionWarning = null;
  if (input.partition) {
    const scoped = scopeToPartition(store, String(input.partition), sinkCandidateFiles, sourceCandidateFiles);
    sinkCandidateFiles = scoped.sinks;
    sourceCandidateFiles = scoped.sources;
    partition = scoped.partition;
    partitionWarning = scoped.warning;
  }

  const codeql = hasCodeqlDb(resolvedTarget);
  const joern = hasJoernCpg(resolvedTarget);
  const backends = {
    codeql: { available: codeql.built, dbDir: store.codeqlDbDir, languages: codeql.languages ?? [] },
    joern: { available: joern.built, cpgPath: store.joernCpgPath },
    treeSitter: { available: true },
    joernScriptPath: join(import.meta.dirname ?? resolve("."), "..", "joern", "taint-flows.sc")
  };

  const run = openRun(resolvedTarget, "taint-analysis");
  const warnings = [];
  if (!ctxState.built) warnings.push("no context run found — languages inferred from file extensions; run /context-build (or restart the session) for richer ranking");
  if (!threatModel) warnings.push("no threat-model.json — ranking proceeds without threat-model CWE boost; /threat-model improves it");
  if (!threatIntel) warnings.push("no threat-intel.json — ranking proceeds without live-CVE CWE boost; /threat-intel ranks bug classes seen in recent CVEs for this stack first");
  if (!backends.codeql.available && !backends.joern.available) warnings.push("no CodeQL DB or Joern CPG present — flow tracing will degrade to tree-sitter + same-file linking (linked/candidate evidence, no path evidence)");
  if (partitionWarning) warnings.push(partitionWarning);
  if (partition) warnings.push(`scoped to partition "${partition.label}" (${partition.id}): ${sinkCandidateFiles.length} sink / ${sourceCandidateFiles.length} source candidate files`);

  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    contextBuilt: ctxState.built,
    languages,
    threatModelPresent: Boolean(threatModel),
    minEvidenceLevel,
    partition,
    rankedCatalog: ranked,
    structuralQueries,
    candidateFiles: { sinks: sinkCandidateFiles, sources: sourceCandidateFiles },
    backends,
    references: artifactSnapshot(resolvedTarget),
    warnings,
    input
  });

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    sinksDraftPath: join(run.runDir, "draft.sinks.json"),
    sourcesDraftPath: join(run.runDir, "draft.sources.json"),
    flowsDraftPath: join(run.runDir, "draft.flows.json"),
    findingsDraftPath: join(run.runDir, "draft.findings.json"),
    partition,
    rankedCatalogCount: ranked.length,
    candidateFileCount: { sinks: sinkCandidateFiles.length, sources: sourceCandidateFiles.length },
    backends,
    warnings,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "taint-analysis-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("taint-analysis-prepare --target <path> [--partition <id|label>] [--input '{\"maxCatalogEntries\":20,\"minEvidenceLevel\":\"linked\"}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file", "partition"] });
  if (!flags.target) {
    console.error("taint-analysis-prepare: --target is required");
    process.exit(1);
  }
  const input = loadInput(flags);
  if (flags.partition) input.partition = flags.partition;
  emitResult(prepareTaintAnalysis(flags.target, input));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
