#!/usr/bin/env node
// Prepare phase for /logic-hunt — the business-logic / invariant-violation track.
//
// Taint, SAST, crypto and sharp-edges are all pattern-bound to a CWE catalog;
// they find bug *classes*. The whole universe of LOGIC flaws — broken atomicity,
// out-of-order state transitions, authorization-by-omission, replay, business-rule
// violations (negative amounts, rounding, quantity underflow) — is invisible to
// them because there's no injection token to grep for; the bug is that the code
// does the wrong *thing*. This producer seeds the logic-hunter with two inputs:
//   1. the system invariants /deep-context already extracted (intended-behavior
//      assertions — the strongest seed: an invariant the agent tries to violate);
//   2. ripgrep probes for code shapes where logic bugs concentrate (money, state
//      machines, transactions, ownership checks).
// The agent then adversarially tries to BREAK each. Deterministic, offline.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { runRg, parseJsonMatches, rankHit, buildGlobs } from "../lib/ripgrep.mjs";

// Probe = a lead for the agent, never a verdict. Each names the logic-bug class
// most likely to live where the shape appears.
const LOGIC_PROBES = [
  { id: "money-arithmetic", logicClass: "business-rule",
    query: "\\b(balance|amount|price|total|credit|debit|refund|quantity|qty|stock)\\b", note: "value arithmetic — check for negatives, rounding, under/overflow, missing bounds" },
  { id: "state-transition", logicClass: "state-machine",
    query: "\\b(status|state|phase|stage)\\s*[:=]\\s*[\"']?(pending|approved|completed|paid|shipped|active|closed|verified)", note: "status assignment — check whether a step can be skipped or reordered" },
  { id: "transaction-boundary", logicClass: "atomicity",
    query: "\\b(begin_?transaction|beginTransaction|commit|rollback|\\.transaction\\(|with_?lock|acquire_?lock|mutex|atomic)\\b", note: "transaction/lock — check for partial commits, TOCTOU, missing rollback" },
  { id: "ownership-check", logicClass: "authz-omission",
    query: "\\b(owner_?id|user_?id|account_?id|tenant_?id)\\b.{0,40}(==|!=|===|\\.equals|===)", note: "ownership comparison — check it actually gates the mutation, and isn't skippable" },
  { id: "check-then-act", logicClass: "ordering",
    query: "\\bif\\s*\\(.{0,60}(exists|is_?valid|has_?|can_?|already)\\b", note: "check-then-act — check for a race window between the check and the use" },
  { id: "idempotency-replay", logicClass: "replay",
    query: "\\b(nonce|idempotenc|request_?id|dedup|replay|once|consumed)\\b", note: "replay/idempotency surface — check whether a request can be applied twice" }
];

function probeCandidates(target, budget) {
  const candidates = [];
  const globs = buildGlobs();
  for (const probe of LOGIC_PROBES) {
    if (candidates.length >= budget) break;
    const result = runRg(target, ["--json", "-n", "-i", "--max-count", "3", "-e", probe.query, ...globs, "."]);
    const remaining = budget - candidates.length;
    const hits = result.ok
      ? parseJsonMatches(result.stdout, 300)
          .sort((a, b) => rankHit(b, "generic") - rankHit(a, "generic"))
          .slice(0, Math.min(3, Math.max(1, remaining)))
      : [];
    for (const hit of hits) {
      candidates.push({
        id: `logic-${probe.id}-${candidates.length + 1}`,
        kind: "probe",
        logicClass: probe.logicClass,
        probe: probe.id,
        note: probe.note,
        filePath: hit.filePath,
        line: hit.line,
        text: hit.text
      });
      if (candidates.length >= budget) break;
    }
  }
  return candidates;
}

// Each deep-context invariant becomes a candidate the agent must try to violate.
function invariantCandidates(invariants, budget) {
  return (invariants ?? []).slice(0, budget).map((inv, i) => ({
    id: `logic-invariant-${i + 1}`,
    kind: "invariant",
    logicClass: inv.logicClass ?? "invariant",
    statement: inv.statement ?? String(inv),
    evidence: inv.evidence ?? inv.anchors ?? [],
    note: "intended-behavior invariant from /deep-context — try to construct a sequence of operations that violates it"
  }));
}

export function prepareLogicHunt(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const maxCandidates = Number(input.maxCandidates ?? 16);

  const deepContext = readJsonIfPresent(join(store.root, "deep-context.json"));
  const invariants = deepContext?.invariants ?? [];
  const warnings = [];
  if (!invariants.length) {
    warnings.push("no .kuzushi/deep-context.json invariants — logic hunting is strongest seeded by intended-behavior invariants; run /deep-context first. Proceeding with probe-seeded candidates only.");
  }

  // Invariants get priority on the budget (the strongest seed), probes fill the rest.
  const invCands = invariantCandidates(invariants, Math.ceil(maxCandidates / 2));
  const probeCands = probeCandidates(resolvedTarget, maxCandidates - invCands.length);
  const candidates = [...invCands, ...probeCands].slice(0, maxCandidates);

  const run = openRun(resolvedTarget, "logic-hunt");
  run.writeJson("prep.json", { runId: run.runId, runDir: run.runDir, target: resolvedTarget, candidates, warnings, input });

  return {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    draftPath: join(run.runDir, "draft.logic-hunt.json"),
    candidateCount: candidates.length,
    invariantSeedCount: invCands.length,
    warnings,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "logic-hunt-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("logic-hunt-prepare --target <path> [--input '{\"maxCandidates\":16}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("logic-hunt-prepare: --target is required"); process.exit(1); }
  emitResult(prepareLogicHunt(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
