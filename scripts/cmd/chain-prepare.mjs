#!/usr/bin/env node
// Prepare phase for /chain (cross-finding chaining). Gathers the actionable
// findings (open / confirmed / proven, plus needs-evidence leads) with their
// CWE, evidence, and rationale so the chain-finder agent can reason about which
// findings COMPOSE into a higher-impact attack chain (precondition → pivot →
// impact) — e.g. an auth bypass that turns a read-only SSRF into an internal
// RCE. Pure read-only; no baked-in chaining heuristics.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

// Findings worth considering as chain members. Reviewed/noise are excluded —
// a chain is only interesting if its members are live.
const CHAINABLE_STATUS = new Set(["open", "confirmed", "proven", "needs-evidence", "needs-trace", "patched"]);

export function prepareChain(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — run a hunt first (/threat-hunt, /taint-analysis, …)`);

  const findings = (findingsDoc.findings ?? []).filter((f) => CHAINABLE_STATUS.has(f.status));
  if (findings.length < 2) {
    throw new Error(`need at least 2 live findings to chain (have ${findings.length}) — run more hunts first`);
  }

  const members = findings.map((f) => ({
    fingerprint: f.fingerprint,
    source: f.source,
    title: f.title,
    cwe: f.cwe,
    severity: f.severity,
    status: f.status,
    verdict: f.verdict,
    evidence: f.evidence ?? [],
    rationale: f.rationale,
    // surface attack-relevant context the chainer reasons over
    verification: f.verification ? { attackVector: f.verification.attackVector, preconditions: f.verification.preconditions } : null
  }));

  const run = openRun(resolvedTarget, "chain");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    findingsMtime: findingsDoc.generatedAt ?? null,
    memberCount: members.length, findings: members, input
  });

  return {
    ok: true, status: "prepared", target: resolvedTarget, runId: run.runId, runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"), draftPath: join(run.runDir, "draft.chain.json"),
    memberCount: members.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "chain-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("chain-prepare --target <path> [--input '{}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("chain-prepare: --target is required"); process.exit(1); }
  emitResult(prepareChain(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
