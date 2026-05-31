#!/usr/bin/env node
// Prepare phase for /threat-hunt (the Carlini adversarial per-threat review).
// Walks the threat model, builds a source excerpt per threat anchor, and
// enriches each candidate with matching threat-intel (by CWE) + x-ray entry
// points so the agent can attack each threat directly. No baked-in CWE
// branches — the agent does the attack reasoning.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";

// The enclosing function around a threat's first anchor (was ±8 lines); handles
// missing files / directory targets gracefully.
function excerptFor(target, threat) {
  const anchor = threat.affectedFiles?.[0] ?? threat.evidenceAnchors?.[0];
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path)) return { filePath: anchor.filePath, startLine: anchor.startLine ?? 1, missing: true, lines: [] };
  if (statSync(path).isDirectory()) return { filePath: anchor.filePath, startLine: 1, isDirectory: true, lines: [] };
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  return { filePath: anchor.filePath, startLine: anchorLine, lines: enclosingExcerpt(target, anchor.filePath, anchorLine) ?? [] };
}

// threat-intel leads + invariants whose CWE intersects the threat's CWEs —
// these seed the agent's bypass attempts (Step D).
function intelFor(threat, intel) {
  if (!intel) return null;
  const cwes = new Set((threat.relatedCwe ?? []).map((c) => String(c)));
  if (!cwes.size) return null;
  const leads = [...(intel.cves?.stack ?? []), ...(intel.cves?.similarApps ?? [])].filter((l) => cwes.has(l.cwe));
  const invariants = (intel.invariants ?? []).filter((i) => cwes.has(i.cwe));
  return leads.length || invariants.length ? { leads, invariants } : null;
}

export function prepareThreatHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  if (!existsSync(store.threatModelPath)) {
    throw new Error(`${store.threatModelPath} not found — run /threat-model first`);
  }
  const threatModel = JSON.parse(readFileSync(store.threatModelPath, "utf8"));
  const intel = readJsonIfPresent(store.threatIntelPath);
  const entryPoints = readJsonIfPresent(join(store.xRayDir, "entry-points.json"));
  const maxCandidates = Number(input.maxCandidates ?? 12);

  const candidates = (threatModel.threats ?? []).slice(0, maxCandidates).map((threat) => ({
    threatId: threat.id,
    title: threat.title,
    category: threat.category,
    severity: threat.impact,
    relatedCwe: threat.relatedCwe ?? [],
    excerpt: excerptFor(resolvedTarget, threat),
    intel: intelFor(threat, intel)
  }));

  const run = openRun(resolvedTarget, "threat-hunt");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    threatModelMtime: statSync(store.threatModelPath).mtime.toISOString(),
    threatModelSummary: threatModel.summary ?? null,
    threatIntelPresent: Boolean(intel),
    references: artifactSnapshot(resolvedTarget),
    entryPoints: Array.isArray(entryPoints) ? entryPoints.slice(0, 40) : null,
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
    draftPath: join(run.runDir, "draft.threat-hunt.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "threat-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-hunt-prepare --target <path> [--input '{\"maxCandidates\":12}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("threat-hunt-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareThreatHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
