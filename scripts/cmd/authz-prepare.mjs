#!/usr/bin/env node
// Prepare phase for /authz (authorization-model review). Scans for request
// handlers / endpoints and object-access-by-user-supplied-id sites (the IDOR
// core), with surrounding context so the authz-reviewer agent can see whether an
// authorization / ownership check is present. Read-only, deterministic.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs, scopePath } from "../lib/ripgrep.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";

// Two candidate kinds: endpoint definitions (is there an authz gate?) and
// object-by-id access (is there an ownership check? → IDOR).
const AUTHZ_PATTERNS = [
  { id: "endpoint", kind: "endpoint",
    query: "@app\\.(route|get|post|put|delete|patch)|@(Get|Post|Put|Delete|Patch|Request)Mapping|app\\.(get|post|put|delete|patch)\\(|router\\.(get|post|put|delete|patch)\\(|@router\\.(get|post|put|delete|patch)|def\\s+\\w+\\(self,\\s*request" },
  { id: "object-by-id", kind: "idor",
    query: "(findById|findOne|get_object_or_404|find_by_id|getById|\\.find\\(|objects\\.get\\(|Repository\\.findById)\\s*\\([^)]*(params|req\\.(params|query|body)|request\\.|\\bid\\b)" }
];

function collectCandidates(target, maxCandidates, scope = ".", maxHitsPerPattern = 12) {
  const candidates = [];
  const globs = buildGlobs();
  for (const pattern of AUTHZ_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const result = runRg(target, ["--json", "-n", "-S", "--max-count", "8", "-e", pattern.query, ...globs, scope]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `authz-${pattern.id}-${candidates.length + 1}`,
        kind: pattern.kind, filePath: hit.filePath, line: hit.line, text: hit.text,
        excerpt: enclosingExcerpt(target, hit.filePath, hit.line)
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

export function prepareAuthz(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxCandidates = Number(input.maxCandidates ?? 30);
  const candidates = collectCandidates(resolvedTarget, maxCandidates, scopePath(input));

  const run = openRun(resolvedTarget, "authz");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    references: artifactSnapshot(resolvedTarget),
    candidateCount: candidates.length, candidates, input
  });

  return {
    ok: true,
    status: candidates.length ? "prepared" : "no-candidates",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.authz.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "authz-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("authz-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("authz-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareAuthz(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
