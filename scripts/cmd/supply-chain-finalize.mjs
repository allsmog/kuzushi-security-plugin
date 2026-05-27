#!/usr/bin/env node
// Finalize phase for /supply-chain. Validates the per-dependency risk the agent
// assessed, persists .kuzushi/supply-chain.json (every dep + tier), and promotes
// the risky ones into .kuzushi/findings.json (source "supply-chain"): high → a
// finding, medium → a candidate (low is recorded but not promoted).

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings } from "../lib/findings.mjs";

const VALID_TIERS = new Set(["high", "medium", "low"]);
const MIN_RATIONALE_LENGTH = 120;
// high → promoted as an open finding; medium → candidate (needs-evidence); low → not promoted.
const TIER_TO_VERDICT = { high: "finding", medium: "candidate" };
const VERDICT_TO_STATUS = { finding: "open", candidate: "needs-evidence" };

function fail(message) {
  console.error(`supply-chain-finalize: ${message}`);
  process.exit(1);
}

function validate(deps) {
  for (const d of deps) {
    const id = d.name ?? "(unknown)";
    if (!d.name) fail(`a dependency entry is missing name`);
    if (!VALID_TIERS.has(d.riskTier)) {
      fail(`${id}: invalid riskTier "${d.riskTier}"; must be one of ${[...VALID_TIERS].join(", ")}`);
    }
    const rationale = String(d.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Cite the risk factors (maintainers, popularity, CVE history, last release).`);
    }
    if (d.riskTier !== "low" && !d.manifest) {
      fail(`${id}: riskTier "${d.riskTier}" requires a manifest path (evidence anchor).`);
    }
  }
}

export function finalizeSupplyChain(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.supply-chain.json");
  if (!existsSync(draftPath)) fail(`no draft.supply-chain.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.supply-chain.json is not valid JSON"); }
  const deps = Array.isArray(draft.dependencies) ? draft.dependencies : null;
  if (!deps) fail("draft must have a dependencies[] array");

  validate(deps);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.supplyChainPath, json);
  atomicWrite(join(resolvedRunDir, "supply-chain.json"), json);

  const promote = deps.filter((d) => d.riskTier !== "low");
  const newFindings = promote.map((d) => {
    const verdict = TIER_TO_VERDICT[d.riskTier];
    return {
      source: "supply-chain",
      refId: `${d.ecosystem ?? "dep"}:${d.name}`,
      title: d.title ?? `${d.riskTier}-risk dependency: ${d.name}`,
      severity: d.riskTier === "high" ? "high" : "medium",
      cwe: (Array.isArray(d.cwe) ? d.cwe[0] : d.cwe) ?? "CWE-1104",
      verdict,
      status: VERDICT_TO_STATUS[verdict],
      evidence: d.manifest ? [{ filePath: d.manifest, startLine: d.line ?? 1 }] : [],
      rationale: String(d.rationale ?? ""),
      nextChecks: Array.isArray(d.nextChecks) ? d.nextChecks : []
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const tierCounts = deps.reduce((acc, d) => { acc[d.riskTier] = (acc[d.riskTier] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "supply-chain-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    depCount: deps.length, tierCounts, promotedCount: promote.length,
    supplyChainPath: store.supplyChainPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("supply-chain-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeSupplyChain(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
