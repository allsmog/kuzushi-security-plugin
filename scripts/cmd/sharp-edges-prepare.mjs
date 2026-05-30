#!/usr/bin/env node
// Prepare phase for /sharp-edges. Scans for footgun-prone API/config patterns —
// the shapes where the SECURE path isn't the default and a developer can trip
// into an insecure state. Hands the sharp-edges-analyzer agent a candidate
// worklist; the agent applies the adversary lens and triages. Deterministic.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs, scopePaths } from "../lib/ripgrep.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";

// Footgun signals grouped by sharp-edges category. These are LEADS — the agent
// confirms whether each is a real misuse-prone edge for the stated adversary.
const FOOTGUN_PATTERNS = [
  { id: "alg-confusion", category: "algorithm-selection",
    query: "alg['\"]?\\s*[:=]\\s*['\"]?none|algorithms?\\s*[:=].*HS256|verify\\([^)]*algorithms?\\s*=|jwt\\.decode\\([^)]*verify\\s*=\\s*False|MD5|DES|RC4|ECB|md5\\(|new MessageDigest" },
  { id: "dangerous-default", category: "dangerous-defaults",
    query: "verify\\s*=\\s*False|InsecureSkipVerify\\s*[:=]\\s*true|rejectUnauthorized\\s*[:=]\\s*false|CURLOPT_SSL_VERIFY(PEER|HOST)\\s*,\\s*0|check_hostname\\s*=\\s*False|trustAllCerts|ALLOW_ALL_HOSTNAME" },
  { id: "config-cliff", category: "configuration-cliff",
    query: "csrf\\w*\\s*[:=]\\s*(false|off|disabled)|debug\\s*[:=]\\s*True|Access-Control-Allow-Origin['\"]?\\s*[:,]\\s*['\"]\\*|cors\\([^)]*origin\\s*[:=]\\s*['\"]?\\*|secure\\s*[:=]\\s*false|httpOnly\\s*[:=]\\s*false" },
  { id: "silent-failure", category: "silent-failures",
    query: "except\\s*:\\s*pass|catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}|rescue\\s*=>\\s*\\w+\\s*$|_ = err|err\\s*!=\\s*nil\\s*\\{\\s*\\}|on_error\\s*[:=]\\s*['\"]?(ignore|continue)" },
  { id: "stringly-typed", category: "stringly-typed-security",
    query: "role\\s*==\\s*['\"]admin['\"]|permission\\s*==\\s*['\"]|hasRole\\(['\"]|authorize\\(['\"][^'\"]+['\"]\\)|if\\s+user\\.role\\s*===?\\s*['\"]" }
];

function collectCandidates(target, maxCandidates, scopes = ["."], maxHitsPerPattern = 6) {
  const candidates = [];
  const globs = buildGlobs();
  for (const pattern of FOOTGUN_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const result = runRg(target, ["--json", "-n", "-S", "--max-count", "4", "-e", pattern.query, ...globs, ...scopes]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `sharp-edges-${pattern.id}-${candidates.length + 1}`,
        pattern: pattern.id,
        category: pattern.category,
        filePath: hit.filePath,
        line: hit.line,
        text: hit.text,
        excerpt: enclosingExcerpt(target, hit.filePath, hit.line)
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

export function prepareSharpEdges(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxCandidates = Number(input.maxCandidates ?? 30);
  const candidates = collectCandidates(resolvedTarget, maxCandidates, scopePaths(input));

  const run = openRun(resolvedTarget, "sharp-edges");
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
    draftPath: join(run.runDir, "draft.sharp-edges.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "sharp-edges-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("sharp-edges-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("sharp-edges-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareSharpEdges(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
