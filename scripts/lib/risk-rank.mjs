// Risk-ranking for the /deep-scan reader. The deep reader is token-expensive, so
// instead of reading every file we read the highest-risk files first within a
// budget. Ranking signals (all already produced elsewhere in the pipeline):
//   • entry points        — x-ray / code-graph (attacker-reachable surface)
//   • trust boundaries    — deep-context.json (where untrusted meets trusted)
//   • high caller-count   — code-graph symbols (blast radius)
//   • recently changed    — git (fresh bugs cluster in churn)
//   • security-relevant   — path/name heuristic (auth, pay, query, exec, …)
// Deterministic given the same repo + artifacts, so a deep sweep is reproducible.
// CRITICAL: this RANKS, it never silently drops — callers report the unread tail.

import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { readJsonIfPresent, storeFor } from "./artifact-store.mjs";
import { inventory, languageOf } from "./sharding.mjs";

const SECURITY_HINT = /(auth|login|logout|session|token|password|passwd|cred|secret|crypto|cipher|hash|jwt|oauth|saml|admin|payment|billing|charge|checkout|order|invoice|upload|download|exec|command|shell|spawn|query|\bsql\b|database|\bdb\b|deserial|pickle|yaml|xml|template|render|redirect|cors|csrf|permission|role|\bacl\b|tenant|account|\buser\b|route|controller|handler|middleware|validate|sanitiz|escape|webhook|ingest|parse)/i;

function entryPointFiles(store) {
  const set = new Set();
  const ep = readJsonIfPresent(`${store.xRayDir}/entry-points.json`);
  for (const e of Array.isArray(ep) ? ep : []) if (e?.filePath) set.add(norm(e.filePath));
  const cg = readJsonIfPresent(store.codeGraphPath);
  for (const e of cg?.entryPoints ?? []) if (e?.filePath) set.add(norm(e.filePath));
  return set;
}

function trustBoundaryFiles(store) {
  const set = new Set();
  const dc = readJsonIfPresent(store.deepContextPath);
  for (const b of dc?.trustBoundaries ?? []) if (b?.filePath) set.add(norm(b.filePath));
  for (const e of dc?.entryPoints ?? []) if (e?.filePath) set.add(norm(e.filePath));
  return set;
}

// file -> max callerCount of any symbol defined in it (blast-radius proxy).
function callerWeight(store) {
  const cg = readJsonIfPresent(store.codeGraphPath);
  const byFile = new Map();
  for (const s of cg?.symbols ?? []) {
    if (!s?.file) continue;
    const f = norm(s.file);
    byFile.set(f, Math.max(byFile.get(f) ?? 0, Number(s.callerCount) || 0));
  }
  return byFile;
}

function recentlyChanged(target, limit = 80) {
  const set = new Set();
  try {
    const r = spawnSync("git", ["-C", target, "log", "--name-only", "--pretty=format:", "-n", "60"], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    if (r.status === 0) {
      for (const line of `${r.stdout}`.split(/\r?\n/)) {
        const f = line.trim();
        if (f && set.size < limit) set.add(norm(f));
      }
    }
  } catch { /* not a git repo — skip this signal */ }
  return set;
}

function norm(p) {
  return String(p ?? "").replace(/^\.\//, "");
}

function inScope(file, scopeDir) {
  if (!scopeDir || scopeDir === ".") return true;
  return file === scopeDir || file.startsWith(`${scopeDir}/`);
}

// Returns { ranked: [{filePath, language, score, reasons[]}], totalCandidates, budget }
export function rankFiles(target, { maxFiles = 25, scopeDir = "." } = {}) {
  const store = storeFor(target);
  const files = inventory(target).files.filter((f) => inScope(f, scopeDir));
  const entries = entryPointFiles(store);
  const boundaries = trustBoundaryFiles(store);
  const callers = callerWeight(store);
  const changed = recentlyChanged(target);

  const scored = files.map((file) => {
    const reasons = [];
    let score = 0;
    if (entries.has(file)) { score += 5; reasons.push("entry-point"); }
    if (boundaries.has(file)) { score += 4; reasons.push("trust-boundary"); }
    const cw = callers.get(file) ?? 0;
    if (cw > 0) { score += Math.min(3, Math.ceil(cw / 4)); reasons.push(`callers=${cw}`); }
    if (changed.has(file)) { score += 2; reasons.push("recently-changed"); }
    if (SECURITY_HINT.test(file)) { score += 2; reasons.push("security-relevant-path"); }
    return { filePath: file, language: languageOf(file), score, reasons };
  });

  // Stable sort: score desc, then path asc for reproducibility.
  scored.sort((a, b) => b.score - a.score || a.filePath.localeCompare(b.filePath));
  const ranked = scored.slice(0, maxFiles);
  return {
    ranked,
    totalCandidates: scored.length,
    unread: Math.max(0, scored.length - ranked.length),
    budget: { maxFiles, scopeDir }
  };
}
