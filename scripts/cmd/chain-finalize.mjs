#!/usr/bin/env node
// Finalize phase for /chain. Validates each proposed attack chain (≥2 real
// member findings, an ordered narrative, evidence), persists .kuzushi/chains.json,
// and attaches a `chains` ref (the chainIds a finding belongs to) onto each member
// via patchFindings — WITHOUT changing finding status (a chain is an overlay on
// the findings, not a new lifecycle state). Implements the chain-finder the
// findings index has long referenced.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { patchFindings } from "../lib/findings.mjs";

const MIN_NARRATIVE_LENGTH = 120;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, "": 0 };

function fail(message) {
  console.error(`chain-finalize: ${message}`);
  process.exit(1);
}

function chainId(members) {
  return "chain-" + createHash("sha256").update([...members].sort().join("|")).digest("hex").slice(0, 12);
}

export function finalizeChain(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.chain.json");
  if (!existsSync(draftPath)) fail(`no draft.chain.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.chain.json is not valid JSON"); }
  if (!Array.isArray(draft.chains)) fail("draft must have a chains[] array");

  const findingsDoc = readJsonIfPresent(store.findingsPath);
  const known = new Set((findingsDoc?.findings ?? []).map((f) => f.fingerprint));

  const chains = draft.chains.map((c, i) => {
    const members = [...new Set((c.members ?? []).filter(Boolean))];
    if (members.length < 2) fail(`chain ${i}: needs at least 2 distinct member fingerprints`);
    for (const m of members) if (!known.has(m)) fail(`chain ${i}: member ${m} is not a known finding`);
    const narrative = String(c.narrative ?? "");
    if (narrative.length < MIN_NARRATIVE_LENGTH) {
      fail(`chain ${i}: narrative is ${narrative.length} chars (min ${MIN_NARRATIVE_LENGTH}). Walk precondition → pivot → impact across the members.`);
    }
    const id = c.chainId ?? chainId(members);
    return {
      chainId: id,
      title: c.title ?? id,
      members,
      severity: c.severity ?? "high",
      steps: Array.isArray(c.steps) ? c.steps : [],
      narrative,
      evidenceAnchors: Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : []
    };
  });

  const generatedAt = new Date().toISOString();
  const doc = { version: "1.0", generatedAt, target: resolvedTarget, chainCount: chains.length, chains };
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  atomicWrite(store.chainsPath, json);
  atomicWrite(join(resolvedRunDir, "chains.json"), json);

  // Attach the full set of chainIds each finding belongs to (recomputed wholesale,
  // since /chain reasons over all findings each run). Status is left unchanged.
  const chainsByMember = new Map();
  for (const c of chains) for (const m of c.members) {
    if (!chainsByMember.has(m)) chainsByMember.set(m, []);
    chainsByMember.get(m).push(c.chainId);
  }
  const patches = [...chainsByMember.entries()].map(([fingerprint, ids]) => ({ fingerprint, chains: ids }));
  const updated = patches.length ? patchFindings(resolvedTarget, patches) : findingsDoc;

  // Highest-severity chain first, for the report.
  const ranked = [...chains].sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
  const run = openRun(resolvedTarget, "chain-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    chainCount: chains.length, chainsPath: store.chainsPath,
    chains: ranked.map((c) => ({ chainId: c.chainId, title: c.title, severity: c.severity, members: c.members })),
    findingsPath: store.findingsPath, findingsSummary: updated?.summary ?? null
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("chain-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeChain(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
