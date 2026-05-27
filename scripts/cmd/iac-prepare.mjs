#!/usr/bin/env node
// Prepare phase for /iac (config & container security). Scans Dockerfiles,
// Kubernetes/Compose manifests, and Terraform/IaC for misconfiguration signals,
// and hands the iac-reviewer agent a candidate worklist. The agent confirms each
// is a real misconfig in context. Read-only, deterministic.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit } from "../lib/ripgrep.mjs";

// Misconfig signals grouped by surface. Leads — the agent confirms impact.
const IAC_PATTERNS = [
  { id: "container-privileged", surface: "container", cwe: "CWE-250",
    glob: ["*.yml", "*.yaml", "Dockerfile*", "docker-compose*"],
    query: "privileged:\\s*true|--privileged|hostPID:\\s*true|hostNetwork:\\s*true|hostIPC:\\s*true|securityContext:[^\\n]*\\n[^\\n]*runAsUser:\\s*0|allowPrivilegeEscalation:\\s*true" },
  { id: "container-root", surface: "container", cwe: "CWE-250",
    glob: ["Dockerfile*"],
    query: "^USER\\s+root|^USER\\s+0\\b" },
  { id: "image-unpinned", surface: "container", cwe: "CWE-1357",
    glob: ["Dockerfile*", "*.yml", "*.yaml"],
    query: "FROM\\s+[^\\s]+:latest|image:\\s*[^\\s]+:latest|FROM\\s+[^@\\s:]+\\s*$" },
  { id: "secret-in-config", surface: "secrets", cwe: "CWE-798",
    glob: ["Dockerfile*", "*.yml", "*.yaml", "*.tf", "*.tfvars", "*.env"],
    query: "(password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\\s*[:=]\\s*['\"][^'\"$\\{][^'\"]{3,}" },
  { id: "network-exposed", surface: "network", cwe: "CWE-668",
    glob: ["*.tf", "*.yml", "*.yaml", "docker-compose*"],
    query: "0\\.0\\.0\\.0/0|cidr_blocks\\s*=\\s*\\[\\s*['\"]0\\.0\\.0\\.0/0|::/0|publiclyAccessible\\s*=\\s*true|0\\.0\\.0\\.0:" },
  { id: "storage-public", surface: "cloud", cwe: "CWE-732",
    glob: ["*.tf"],
    query: "acl\\s*=\\s*['\"]public-read|block_public_(acls|policy)\\s*=\\s*false|force_destroy\\s*=\\s*true" },
  { id: "tls-disabled", surface: "transport", cwe: "CWE-319",
    glob: ["*.tf", "*.yml", "*.yaml"],
    query: "insecure\\s*=\\s*true|skip_tls_verify\\s*=\\s*true|sslmode=disable|encrypt(ion|ed)?\\s*=\\s*false" }
];

function collectCandidates(target, maxCandidates, maxHitsPerPattern = 6) {
  const candidates = [];
  for (const pattern of IAC_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const globs = pattern.glob.flatMap((g) => ["-g", g]);
    const result = runRg(target, ["--json", "-n", "-i", "--max-count", "4", "-e", pattern.query, ...globs, "."]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 200)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `iac-${pattern.id}-${candidates.length + 1}`,
        pattern: pattern.id, surface: pattern.surface, cwe: pattern.cwe,
        filePath: hit.filePath, line: hit.line, text: hit.text
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

export function prepareIac(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxCandidates = Number(input.maxCandidates ?? 30);
  const candidates = collectCandidates(resolvedTarget, maxCandidates);

  const run = openRun(resolvedTarget, "iac");
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
    draftPath: join(run.runDir, "draft.iac.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "iac-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("iac-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("iac-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareIac(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
