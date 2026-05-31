#!/usr/bin/env node
// Prepare phase for /logic-hunt (business-logic flaw review). Taint/SAST tools
// find injection; they're blind to "charge the card, then check the balance" and
// "replay the same purchase twice". This scans for the *shapes* of business-logic
// bugs — money/state mutations, multi-step transactions, price/quantity math, and
// status transitions — with surrounding context so the logic-hunter agent can
// judge whether an idempotency key / lock / transaction / ownership invariant
// actually protects the action. Read-only, deterministic.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs, scopePaths } from "../lib/ripgrep.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";

// Each pattern is a *shape*, not a bug. The agent decides if the protecting
// invariant (idempotency key, lock, DB transaction, ownership/limit check) is
// present and sufficient — that's the whole job.
const LOGIC_PATTERNS = [
  { id: "money-mutation", logicClass: "transaction-atomicity",
    query: "\\b(charge|capture|refund|transfer|withdraw|deposit|debit|credit|payout|settle)\\s*\\(" },
  { id: "balance-update", logicClass: "toctou-race",
    query: "\\b(balance|inventory|stock|quantity|credits|points)\\b\\s*[-+]?=" },
  { id: "state-transition", logicClass: "state-machine",
    query: "\\b(status|state|stage|phase)\\b\\s*=\\s*['\\\"]?(completed|complete|paid|settled|shipped|approved|active|fulfilled|closed)" },
  { id: "idempotency-surface", logicClass: "idempotency",
    query: "\\b(create_?order|place_?order|submit|checkout|process_?payment|redeem|apply_?coupon|claim)\\s*\\(" },
  { id: "price-math", logicClass: "price-quantity",
    query: "\\b(price|amount|total|subtotal|discount|tax|fee)\\b\\s*[-+*]=?|\\*\\s*\\b(qty|quantity|count|units)\\b" }
];

function collectCandidates(target, maxCandidates, scopes = ["."], maxHitsPerPattern = 8) {
  const candidates = [];
  const globs = buildGlobs();
  for (const pattern of LOGIC_PATTERNS) {
    if (candidates.length >= maxCandidates) break;
    const result = runRg(target, ["--json", "-n", "-S", "--max-count", "6", "-e", pattern.query, ...globs, ...scopes]);
    const remaining = maxCandidates - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(maxHitsPerPattern, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `logic-${pattern.id}-${candidates.length + 1}`,
        logicClass: pattern.logicClass,
        pattern: pattern.id,
        filePath: hit.filePath, line: hit.line, text: hit.text,
        excerpt: enclosingExcerpt(target, hit.filePath, hit.line)
      });
      if (candidates.length >= maxCandidates) break;
    }
  }
  return candidates;
}

export function prepareLogicHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const maxCandidates = Number(input.maxCandidates ?? 30);
  const candidates = collectCandidates(resolvedTarget, maxCandidates, scopePaths(input));

  const run = openRun(resolvedTarget, "logic-hunt");
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
    draftPath: join(run.runDir, "draft.logic-hunt.json"),
    candidateCount: candidates.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "logic-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("logic-hunt-prepare --target <path> [--input '{\"maxCandidates\":30}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("logic-hunt-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareLogicHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
