#!/usr/bin/env node
// Prepare phase for /verify (exploitability verification). Reads the shared
// findings index, selects the open / trace-needed findings (regardless of which
// producer wrote them — threat-hunt, taint-analysis, …), builds a source excerpt
// around each finding's primary evidence anchor, and enriches with matching
// threat-intel by CWE so the agent can reconstruct a concrete trigger. No baked-in
// CWE branches — the agent does the exploitability reasoning. Read-only.

import { existsSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, artifactSnapshot, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { enclosingExcerpt } from "../lib/excerpt.mjs";
import { recommendedProofLane } from "../lib/sanitizers.mjs";
import { investigateFile, joernAvailable } from "../lib/scoped-cpg.mjs";

// Map a memory-class candidate's CWE to the scoped-CPG query that models it.
const CWE_TO_CPG_QUERY = { "416": "use-after-free.sc", "415": "double-free.sc", "190": "integer-overflow.sc", "191": "integer-overflow.sc", "787": "integer-overflow.sc", "125": "integer-overflow.sc" };
function cpgQueryFor(cwe) {
  const n = String(Array.isArray(cwe) ? cwe[0] : (cwe ?? "")).replace(/^CWE-/i, "").trim();
  return CWE_TO_CPG_QUERY[n] ?? "use-after-free.sc";
}

// The N independent lenses a verification panel uses — each verifier attacks the
// finding from one angle so the panel catches failure modes a single pass misses.
const PANEL_LENSES = [
  { id: "reachability", focus: "Is the source genuinely attacker-controlled, and is the sink reachable on some real execution path from it? Trace it; default to NOT-reachable if you can't show the path." },
  { id: "guard-bypass", focus: "Enumerate every guard/validation/sanitizer between source and sink and try to bypass each. Confirmed only if all are bypassable; otherwise name the one that holds." },
  { id: "impact", focus: "If it fires, what is the concrete, attacker-meaningful impact (RCE/data theft/authz bypass/DoS)? Distinguish a real exploit from a theoretical one." }
];

// The enclosing function around a finding's first evidence anchor (was ±10 lines).
function excerptFor(target, anchor) {
  if (!anchor?.filePath) return null;
  const path = resolve(target, anchor.filePath);
  if (!existsSync(path)) return { filePath: anchor.filePath, startLine: anchor.startLine ?? 1, missing: true, lines: [] };
  if (statSync(path).isDirectory()) return { filePath: anchor.filePath, startLine: 1, isDirectory: true, lines: [] };
  const anchorLine = Math.max(1, Number(anchor.startLine ?? 1));
  return { filePath: anchor.filePath, startLine: anchorLine, lines: enclosingExcerpt(target, anchor.filePath, anchorLine) ?? [] };
}

// threat-intel CVE leads + invariants whose CWE matches the finding's CWE — these
// seed the agent's bypass/trigger construction.
function intelFor(finding, intel) {
  if (!intel || !finding.cwe) return null;
  const cwe = String(finding.cwe);
  const leads = [...(intel.cves?.stack ?? []), ...(intel.cves?.similarApps ?? [])].filter((l) => String(l.cwe) === cwe);
  const invariants = (intel.invariants ?? []).filter((i) => String(i.cwe) === cwe);
  return leads.length || invariants.length ? { leads, invariants } : null;
}

// Verify the findings that are worth confirming: anything still open (threat-hunt
// "exploitable", taint-analysis "finding"), plus the ones that explicitly asked
// for an agent trace. Skip reviewed / noise / needs-evidence.
function isCandidate(finding) {
  return finding.status === "open" || finding.verdict === "needs-active-agent-trace";
}

export function prepareVerify(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) {
    throw new Error(`${store.findingsPath} not found — run /threat-hunt (or /taint-analysis) first`);
  }
  const intel = readJsonIfPresent(store.threatIntelPath);
  const maxCandidates = Number(input.maxCandidates ?? 12);
  // panel = N independent verifiers per finding (majority vote). 1 = classic
  // single-pass /verify. Clamp to the number of defined lenses.
  const panel = Math.min(PANEL_LENSES.length, Math.max(1, Number(input.panel ?? 1)));

  const candidates = (findingsDoc.findings ?? [])
    .filter(isCandidate)
    .slice(0, maxCandidates)
    .map((f) => ({
      findingFingerprint: f.fingerprint,
      source: f.source,
      refId: f.refId,
      title: f.title,
      severity: f.severity,
      cwe: f.cwe,
      verdict: f.verdict,
      status: f.status,
      rationale: f.rationale,
      evidence: f.evidence ?? [],
      excerpt: excerptFor(resolvedTarget, (f.evidence ?? [])[0]),
      intel: intelFor(f, intel),
      // Default proof DRIVER (Lever 2): memory-corruption claims are confirmed by RUNNING
      // them under a sanitizer (/sanitize-pov), not by re-reading — reading misses exactly
      // this class. The verifier should drive memory findings to execution proof.
      recommendedProofLane: recommendedProofLane(f)
    }));

  // Auto-wire the scoped-CPG memory lane (roadmap Phase 1/2): for memory-class candidates,
  // build a light CPG bounded to the suspect file's subsystem and attach the interprocedural
  // source→sink flows as `cpgLeads` — so the verifier sees a cross-function UAF/overflow the
  // single-file excerpt can't show, WITHOUT the agent remembering to run cpg-scan by hand.
  // Best-effort + bounded: only when joern is installed, only memory candidates, deduped by
  // file and capped, each timeboxed. Disable with input.cpgEnrich === false.
  if (input.cpgEnrich !== false && joernAvailable()) {
    const cap = Number(input.maxCpgFiles ?? 3);
    const seen = new Set();
    for (const c of candidates) {
      if (seen.size >= cap) break;
      if (c.recommendedProofLane !== "sanitize-pov") continue;
      const file = c.evidence?.[0]?.filePath;
      if (!file || seen.has(file)) continue;
      seen.add(file);
      try {
        const r = investigateFile(resolvedTarget, file, join(import.meta.dirname ?? resolve("."), "..", "..", "packs", "starter", "joern", cpgQueryFor(c.cwe)), { mode: "dir" });
        const leads = (r.flows ?? []).filter((fl) => String(fl.filePath) && (String(file).endsWith(String(fl.filePath)) || String(fl.filePath).endsWith(String(file).split("/").pop())));
        if (leads.length) for (const cc of candidates) if (cc.evidence?.[0]?.filePath === file) cc.cpgLeads = leads.slice(0, 10);
      } catch { /* best-effort — verification proceeds without the CPG lead */ }
    }
  }

  const lenses = PANEL_LENSES.slice(0, panel);
  const run = openRun(resolvedTarget, "verify");
  run.writeJson("prep.json", {
    runId: run.runId,
    runDir: run.runDir,
    target: resolvedTarget,
    findingsMtime: statSync(store.findingsPath).mtime.toISOString(),
    findingsSummary: findingsDoc.summary ?? null,
    threatIntelPresent: Boolean(intel),
    references: artifactSnapshot(resolvedTarget),
    panel,
    lenses,
    candidates,
    input
  });

  const cmdDir = import.meta.dirname ?? resolve(".");
  const base = {
    ok: true,
    status: "prepared",
    target: resolvedTarget,
    runId: run.runId,
    runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"),
    candidateCount: candidates.length,
    panel
  };
  if (panel === 1) {
    return {
      ...base,
      draftPath: join(run.runDir, "draft.verify.json"),
      assembleCommand: `node "${join(cmdDir, "verify-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
    };
  }
  // Panel mode: one draft per lens (draft.verify.0.json …), aggregated by consensus.
  return {
    ...base,
    lenses,
    draftPaths: lenses.map((l, i) => ({ lens: l.id, path: join(run.runDir, `draft.verify.${i}.json`) })),
    assembleCommand: `node "${join(cmdDir, "verify-panel-assemble.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("verify-prepare --target <path> [--input '{\"maxCandidates\":12}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) {
    console.error("verify-prepare: --target is required");
    process.exit(1);
  }
  emitResult(prepareVerify(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
