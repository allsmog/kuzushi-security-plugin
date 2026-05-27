#!/usr/bin/env node
// Prepare phase for /systems-hunt (native / parser / memory-safety review).
// Scans the repo for systems patterns (ripgrep, ranked by the "systems"
// profile), merges in threat-model / threat-intel candidates, and writes a
// per-candidate worklist for the systems-hunter agent. No baked-in verdicts —
// the agent confirms reachability + memory-safety impact.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs } from "../lib/ripgrep.mjs";

// Native boundaries, unsafe memory primitives, binary/archive parsers, plus two
// high-signal systems sinks (deserialization, process exec).
const SYSTEMS_PATTERNS = [
  { id: "native-load", query: "System\\.loadLibrary|JNIEXPORT|external fun|native\\s+", concern: "native / JNI boundary", cwe: ["CWE-119"] },
  { id: "unsafe-memory", query: "Unsafe|ByteBuffer\\.allocateDirect|memcpy|strcpy|strcat|sprintf|gets\\(|alloca\\(", concern: "manual memory or unsafe primitive", cwe: ["CWE-119", "CWE-787"] },
  { id: "archive-parser", query: "ZipInputStream|GZIPInputStream|Inflater|ByteArrayInputStream|TarInputStream", concern: "binary/archive parser boundary", cwe: ["CWE-400", "CWE-787"] },
  { id: "deserialize", query: "ObjectInputStream|readObject\\(|Marshal\\.load|pickle\\.loads?|yaml\\.load\\b|unserialize\\(", concern: "unsafe deserialization boundary", cwe: ["CWE-502"] },
  { id: "process-exec", query: "Runtime\\.exec|ProcessBuilder|exec\\(|execve|popen\\(|system\\(", concern: "process execution sink", cwe: ["CWE-78"] }
];

const NEXT_CHECKS = [
  "Identify native boundaries, binary parsers, or unsafe memory operations reachable from external input.",
  "Check whether the tree-sitter / codeql / joern backends can provide call references around this boundary.",
  "Separate app-owned code from generated, vendored, or runtime-library code before reporting."
];

function collectScannedCandidates(target, maxCandidates, maxHitsPerPattern = 6) {
  const candidates = [];
  const globs = buildGlobs();
  for (const pattern of SYSTEMS_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const result = runRg(target, ["--json", "-n", "-S", "--max-count", "3", "-e", pattern.query, ...globs, "."]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "systems") - rankHit(a, "systems"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `systems-hunt-${pattern.id}-${candidates.length + 1}`,
        pattern: pattern.id,
        concern: pattern.concern,
        cwe: pattern.cwe,
        filePath: hit.filePath,
        line: hit.line,
        text: hit.text,
        proofLevel: "artifact-review-only",
        nextChecks: NEXT_CHECKS
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

function threatModelCandidates(threatModel, limit) {
  if (!Array.isArray(threatModel?.threats)) return [];
  return threatModel.threats.slice(0, limit).map((threat, i) => {
    const anchor = threat.affectedFiles?.[0] ?? threat.evidenceAnchors?.[0] ?? {};
    return {
      id: `systems-hunt-threat-model-${i + 1}`,
      pattern: "threat-model",
      concern: threat.title ?? "threat-model candidate",
      cwe: threat.relatedCwe ?? [],
      filePath: anchor.filePath,
      line: anchor.startLine,
      text: threat.attackVector ?? threat.description ?? "",
      proofLevel: "artifact-review-only",
      nextChecks: NEXT_CHECKS
    };
  });
}

function threatIntelCandidates(intel, limit) {
  const leads = [...(intel?.cves?.stack ?? []), ...(intel?.cves?.similarApps ?? [])];
  return leads.slice(0, limit).map((lead, i) => ({
    id: `systems-hunt-threat-intel-${i + 1}`,
    pattern: "threat-intel",
    concern: lead.title ?? lead.cve ?? "threat-intel lead",
    cwe: lead.cwe ? [lead.cwe] : [],
    filePath: null,
    line: null,
    text: (lead.checksToRun ?? []).join("; "),
    proofLevel: "artifact-review-only",
    nextChecks: NEXT_CHECKS
  }));
}

export function prepareSystemsHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxCandidates = Number(input.maxCandidates ?? 30);

  const scanned = collectScannedCandidates(resolvedTarget, maxCandidates);
  const remaining = Math.max(0, maxCandidates - scanned.length);
  const threatModel = readJsonIfPresent(store.threatModelPath);
  const intel = readJsonIfPresent(store.threatIntelPath);
  const candidates = [
    ...scanned,
    ...threatModelCandidates(threatModel, Math.ceil(remaining / 2)),
    ...threatIntelCandidates(intel, Math.floor(remaining / 2))
  ].slice(0, maxCandidates);

  const run = openRun(resolvedTarget, "systems-hunt");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    references: artifactSnapshot(resolvedTarget),
    threatModelPresent: Boolean(threatModel),
    threatIntelPresent: Boolean(intel),
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
    draftPath: join(run.runDir, "draft.systems-hunt.json"),
    candidateCount: candidates.length,
    scannedCount: scanned.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "systems-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("systems-hunt-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("systems-hunt-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSystemsHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
