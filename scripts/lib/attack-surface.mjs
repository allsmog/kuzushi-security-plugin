// Attack-surface partitioning for /sweep (the deterministic half of ROADMAP L5's
// "ensemble discovery") and for the discovery-by-execution lane's recon seeds.
//
// The recon-agent partition in Anthropic's defending-code reference is an LLM call;
// /sweep's prepare is contractually deterministic ("same repo → same plan"), so we
// derive the partition from signals that are ALREADY computed — risk-rank's per-file
// score + reasons[] tags — with no agent in the loop. We keep the files an attacker
// can actually reach (input processors, entry points, framework routes, trust
// boundaries), cluster them into subsystems, and cap the count so the overlay stays
// bounded. Nothing is dropped: subsystems ride ON TOP of the dir-shards, which remain
// the coverage backstop. (Inspired by the reference's recon partition; our own wording.)

import { rankFiles } from "./risk-rank.mjs";
import { languageOf } from "./sharding.mjs";

// risk-rank reasons[] that mean "an attacker's data reaches this file". An
// `entry-defs=<n>` tag is per-file dynamic, so match it by prefix.
const REACHABLE_TAGS = new Set(["input-processor", "entry-point", "framework-route", "trust-boundary", "dispatch-entry"]);
function isReachable(reasons = []) {
  return reasons.some((r) => REACHABLE_TAGS.has(r) || r.startsWith("entry-defs="));
}

function topDir(file) {
  const i = file.indexOf("/");
  return i === -1 ? "." : file.slice(0, i);
}
function stem(file) {
  const base = file.slice(file.lastIndexOf("/") + 1);
  const dot = base.indexOf(".");
  return dot === -1 ? base : base.slice(0, dot);
}

// Partition the attacker-reachable surface into independent subsystems. Subsystem key =
// "<top-level dir>/<basename stem>", so a file and its header/sibling cluster together.
// Deterministic: rankFiles is deterministic and the sort has a stable tiebreak.
// Returns { subsystems:[{ id, key, files[], languages[], score, reasons[] }], … }.
export function partitionAttackSurface(target, { maxFilesPerShard = 60, maxSubsystems = 15 } = {}) {
  const { ranked } = rankFiles(target, { maxFiles: Number.MAX_SAFE_INTEGER, scopeDir: "." });
  const reachable = ranked.filter((f) => isReachable(f.reasons));

  const groups = new Map();
  for (const f of reachable) {
    const key = `${topDir(f.filePath)}/${stem(f.filePath)}`;
    if (!groups.has(key)) groups.set(key, { key, files: [], score: 0, reasons: new Set() });
    const g = groups.get(key);
    g.files.push(f.filePath);
    g.score += f.score ?? 0;
    for (const r of f.reasons ?? []) g.reasons.add(r);
  }

  // Highest aggregate score first; key asc as the deterministic tiebreak. Cap the
  // number of subsystems (the overlay must stay bounded) and the files per subsystem
  // (so one giant cluster doesn't blow a hunter's budget). The tail still rides the
  // dir-shards, so nothing is dropped from coverage.
  const sorted = [...groups.values()].sort((a, b) => b.score - a.score || a.key.localeCompare(b.key));
  const subsystems = sorted.slice(0, maxSubsystems).map((g, i) => {
    const files = g.files.slice(0, maxFilesPerShard);
    const languages = [...new Set(files.map((f) => languageOf(f)).filter((l) => l && l !== "Other"))].sort();
    return { id: `subsystem-${i + 1}`, key: g.key, files, languages, score: g.score, reasons: [...g.reasons].sort() };
  });

  return {
    subsystems,
    subsystemCount: subsystems.length,
    reachableFileCount: reachable.length,
    tailGroupCount: Math.max(0, sorted.length - subsystems.length)
  };
}
