#!/usr/bin/env node
// Prepare phase for /crypto-review. Scans for crypto-misuse signals — non-
// constant-time comparison of secrets (timing side-channels), missing / compiler-
// elidable zeroization of secrets, and non-cryptographic RNG used for secrets —
// and hands the crypto-reviewer agent a candidate worklist. The agent confirms
// the value is secret-derived and assesses impact. Deterministic; offline.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs } from "../lib/ripgrep.mjs";

// Each entry is a lead for the agent — not a verdict. Categories mirror the two
// Trail of Bits skills this ports (constant-time-analysis, zeroize-audit) plus
// crypto-grade RNG misuse.
const CRYPTO_PATTERNS = [
  // Variable-time comparison primitives — only a problem on SECRETS (agent confirms).
  { id: "nonct-memcmp", category: "timing-side-channel",
    query: "\\b(memcmp|strcmp|strncmp)\\s*\\(", cwe: "CWE-208" },
  // A comparison operator / .equals near a secret-ish identifier on the same line,
  // with the secret on EITHER side of the operator (`a == secret` or `secret == a`).
  { id: "nonct-secret-compare", category: "timing-side-channel",
    query: "(==|!=|\\.equals\\(|\\.compare\\().{0,50}(hmac|\\bmac\\b|signature|\\bsig\\b|token|secret|password|passwd|digest|auth.?tag|api.?key|csrf)|(hmac|\\bmac\\b|signature|\\bsig\\b|token|secret|password|passwd|digest|auth.?tag|api.?key|csrf).{0,50}(==|!=|\\.equals\\(|\\.compare\\()", cwe: "CWE-208" },
  // Zeroization: secret buffers cleared with memset (often optimized away) — should
  // use explicit_bzero / SecureZeroMemory / sodium_memzero / the zeroize crate.
  { id: "elidable-zero", category: "missing-zeroization",
    query: "memset\\s*\\([^,]*(key|secret|password|passwd|seed|mnemonic|priv|token)[^,]*,\\s*0", cwe: "CWE-14" },
  // Secret-bearing buffers/vars (agent checks whether they are zeroized after use).
  { id: "secret-lifetime", category: "missing-zeroization",
    query: "\\b(private_?key|secret_?key|master_?key|mnemonic|seed_?phrase|passphrase)\\b", cwe: "CWE-226" },
  // Non-cryptographic RNG used to mint secrets/tokens/keys (term on either side).
  { id: "weak-crypto-rng", category: "weak-crypto-rng",
    query: "(Math\\.random|\\brand\\s*\\(|\\bsrand\\s*\\(|random\\.random\\(|mt_rand|new Random\\().{0,60}(token|secret|\\bkey\\b|nonce|\\biv\\b|salt|password|otp|session)|(token|secret|\\bkey\\b|nonce|\\biv\\b|salt|password|otp|session).{0,60}(Math\\.random|\\brand\\s*\\(|\\bsrand\\s*\\(|random\\.random\\(|mt_rand|new Random\\()", cwe: "CWE-338" }
];

function collectCandidates(target, maxCandidates, maxHitsPerPattern = 6) {
  const candidates = [];
  const globs = buildGlobs();
  for (const pattern of CRYPTO_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const result = runRg(target, ["--json", "-n", "-i", "--max-count", "4", "-e", pattern.query, ...globs, "."]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `crypto-review-${pattern.id}-${candidates.length + 1}`,
        pattern: pattern.id,
        category: pattern.category,
        cwe: pattern.cwe,
        filePath: hit.filePath,
        line: hit.line,
        text: hit.text
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

export function prepareCryptoReview(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxCandidates = Number(input.maxCandidates ?? 30);
  const candidates = collectCandidates(resolvedTarget, maxCandidates);

  const run = openRun(resolvedTarget, "crypto-review");
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
    draftPath: join(run.runDir, "draft.crypto-review.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "crypto-review-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("crypto-review-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("crypto-review-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareCryptoReview(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
