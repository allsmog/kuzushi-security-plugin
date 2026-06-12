// Obligation-routed discovery (roadmap Phase 1).
//
// The file ranker hits a wall: a bug in a low-ranked file is never read, and a cloud
// cluster only beats this by reading EVERYTHING (throughput a laptop lacks). This inverts
// the routing primitive: instead of "rank files, read the top-N whole", it enumerates the
// dangerous SITES (obligations) across the WHOLE repo and ranks THOSE, budgeted by
// obligation count. A dangerous primitive in file #606 still enters the worklist because
// it's an obligation, not because its file ranked — and the agent discharges it in its
// enclosing-function scope (~20 lines), so the same token budget covers far more sites
// than whole-file reading. This is the methodology that flipped the xackdel case in eval.
//
// Deterministic + read-only: same repo → same worklist. The agent reasons; this only
// decides WHICH sites it must discharge and in what order.

import { inventory, languageOf } from "./sharding.mjs";
import { extractObligations } from "./sink-obligations.mjs";
import { rankFiles } from "./risk-rank.mjs";

// Discharge priority by class: how costly is a missed instance of this class, and how
// often is the obligation the actual bug (signal density). Memory-corruption + injection
// score highest; defense-in-depth/nuisance classes lowest. Not a severity — a *triage
// order* for which sites get the scarce discharge budget first.
const CLASS_WEIGHT = {
  "lifetime-free": 10, "int-overflow-size": 10, "command-exec": 10,
  "deserialization": 9, "dynamic-eval": 9,
  "raw-copy": 8, "gc-rooting": 8, "sql-sink": 8,
  "object-authz": 7,
  "fixed-size-buffer": 6, "alloc-arith": 6, "path-fs": 6, "ssrf": 6, "template-xss": 6, "authz-decision": 6,
  "open-redirect": 2
};
const DEFAULT_WEIGHT = 5;

// File reachability → a small additive boost so an obligation on attacker-reachable
// surface outranks the same class in dead/vendored code. Bounded so it can't dominate the
// class weight (we are routing by DANGER, with reachability as a tiebreak — the whole
// point is to NOT let low file rank bury a dangerous site).
function reachBoost(fileScore) {
  if (!Number.isFinite(fileScore) || fileScore <= 0) return 0;
  return Math.min(4, Math.round(Math.log2(fileScore + 1)));
}

// Rank obligations as an ADDITIVE OVERLAY over file-routing (the measured-correct design).
//
// Measured negative result: a worklist that REPLACES file-routing is worse — global
// class-weight ranking buries a low-class bug site (xackdel's fixed-size-buffer) under
// 1,400 higher-class obligations, losing a case file-routing already finds. So the overlay
// covers ONLY the long tail: `excludeTopFiles` files the file-ranker already reads are
// dropped, and obligations are ranked among the REMAINING (sub-budget) files. This can't
// lose a Tier-1 win (those files are still read by the file lane) and adds exactly the
// coverage file-routing misses — a dangerous site in a file ranked below the read budget.
//   excludeTopFiles — how many top file-ranked files the file lane already covers (overlay
//                     skips them). Set to the file-sweep's maxFiles. 0 = rank all files.
//   maxObligations  — overlay discharge budget (worklist length).
//   maxPerFile      — cap per file; even-sampled so a late-file site still survives.
// Returns { obligations: [...], totalSites, totalFiles, unbudgeted, excludedFiles }.
export function rankObligations(target, { scopeDir = ".", maxObligations = 120, maxPerFile = 8, excludeTopFiles = 0 } = {}) {
  const inScope = (f) => scopeDir === "." || f === scopeDir || f.startsWith(`${scopeDir}/`);

  // One rankFiles pass gives a reachability score per file (the tiebreak boost) AND the
  // top-K set the file lane already covers (excluded from the overlay).
  let fileScore = new Map();
  let ranked = [];
  try {
    ({ ranked } = rankFiles(target, { maxFiles: Number.MAX_SAFE_INTEGER, scopeDir }));
    for (const r of ranked) fileScore.set(r.filePath, r.score);
  } catch { /* reachability boost degrades to 0 — class weight still routes */ }
  const covered = new Set(excludeTopFiles > 0 ? ranked.slice(0, excludeTopFiles).map((r) => r.filePath) : []);

  const files = inventory(target).files.filter((f) => inScope(f) && !covered.has(f));

  let totalSites = 0;
  const all = [];
  for (const file of files) {
    let obs;
    try { obs = extractObligations(target, file, { cap: maxPerFile }); } catch { obs = []; }
    if (!obs.length) continue;
    totalSites += obs.length;
    const fs = fileScore.get(file) ?? 0;
    const rb = reachBoost(fs);
    for (const o of obs) {
      const cw = CLASS_WEIGHT[o.kind] ?? DEFAULT_WEIGHT;
      all.push({
        filePath: file, line: o.line, kind: o.kind, obligation: o.obligation, text: o.text,
        language: languageOf(file),
        priority: cw + rb,
        reasons: [`class:${o.kind}(${cw})`, ...(rb ? [`reach+${rb}`] : [])]
      });
    }
  }

  // Highest priority first; stable tiebreak (file, line) for reproducibility.
  all.sort((a, b) => b.priority - a.priority || a.filePath.localeCompare(b.filePath) || a.line - b.line);
  const obligations = all.slice(0, maxObligations);
  return {
    obligations,
    totalSites,
    totalFiles: files.length,
    excludedFiles: covered.size,                              // covered by the file lane (not in overlay)
    unbudgeted: Math.max(0, all.length - obligations.length)  // honest: sub-budget sites NOT in the overlay
  };
}

export const _internals = { CLASS_WEIGHT, reachBoost };
