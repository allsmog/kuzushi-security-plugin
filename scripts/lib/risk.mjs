// Deterministic risk score for ordering findings "fix first".
//
// This makes NO security decision — the verdict (exploitable / confirmed /
// proven) is produced upstream by the producers and the verifier. This module
// only *orders* already-triaged findings so a report (or the SessionStart hook,
// or SARIF) can lead with what a maintainer should fix first. It is pure and
// side-effect-free so every consumer shares one ranking and a unit test can pin
// the order exactly.
//
// The score answers "how much attention does this deserve, now?" — which is
// impact (severity) weighted by how *established* the bug is (a proven RCE
// outranks a same-severity hunch, because a lead may evaporate on inspection and
// a reviewer wastes the least time on what is already triggered), nudged by
// memory-corruption exploitability tier, reachability/blast-radius, and whether
// the finding participates in an attack chain.

// Inherent impact if exploited. The gap between tiers is deliberate so severity
// dominates ties between findings at the same proof state.
const SEVERITY_BASE = {
  critical: 40, high: 30, medium: 18, low: 8,
  info: 4, informational: 4, none: 4
};

// How established the finding is — mirrors the proof ladder in findings.mjs
// (proofStateFor). `patch-planned` ranks high because a fix is in flight and
// wants review; resolved states (remediated/reviewed/noise) score 0 — they
// should be filtered out of "fix first" upstream, but score low if shown.
const PROOF_WEIGHT = {
  proven: 35, "patch-validated": 33, "patch-planned": 20, confirmed: 28,
  "trigger-built": 18, reachable: 12, open: 8, candidate: 3, lead: 0,
  remediated: 0, reviewed: 0, noise: 0
};

// Memory-corruption exploitability tier (from /mem-exploitability). Ordered to
// match its closed tier set: a plausible control-flow hijack is worse than a
// crash. Only present on memory findings; absent → no bump.
const MEM_TIER_BONUS = {
  "likely-code-exec": 18, "control-flow-hijack-plausible": 14,
  "info-leak": 8, dos: 4, "crash-only": 1
};

// For deterministic tie-breaks and any caller that wants a coarse severity order.
const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, informational: 1, none: 0 };

export function severityRank(severity) {
  return SEVERITY_RANK[String(severity ?? "").toLowerCase()] ?? 2;
}

// Blast-radius contribution: log-scaled so a hub function (hundreds of callers)
// can't swamp severity, and capped at +15. 0 callers → 0; ~9 → +5; ~99 → +10.
function blastRadiusBonus(callerCount) {
  if (!(callerCount > 0)) return 0;
  return Math.min(15, Math.round(5 * Math.log10(1 + callerCount)));
}

// Score one finding in [0, 100]. `blastRadius` is an optional caller count for
// the finding's location (see /report's code-graph lookup); 0 when unknown.
export function scoreFinding(finding, { blastRadius = 0 } = {}) {
  const severity = String(finding.severity ?? "medium").toLowerCase();
  let score = SEVERITY_BASE[severity] ?? 15;

  score += PROOF_WEIGHT[finding.proofState] ?? 0;

  // Corroborating signals that can lead the proofState (e.g. a verifier confirmed
  // it but status hasn't been re-summarized), and the penalty for a finding the
  // verifier judged not-exploitable (usually already status:reviewed, harmless here).
  if (finding.verification?.verdict === "confirmed-exploitable") score += 4;
  if (finding.verification?.verdict === "not-exploitable") score -= 20;
  if (finding.poc?.proofVerdict === "exploited") score += 6;

  const tier = finding.exploitability?.tier;
  if (tier && MEM_TIER_BONUS[tier]) score += MEM_TIER_BONUS[tier];

  score += blastRadiusBonus(blastRadius);

  // Chain membership compounds impact: a bug that is a step in a documented
  // attack chain is worth more than the same bug in isolation.
  if (Array.isArray(finding.chains) && finding.chains.length) score += 5;

  return Math.max(0, Math.min(100, Math.round(score)));
}

// Rank findings highest-risk first. `blastRadiusFor(finding)` returns an optional
// caller count per finding (default: unknown → 0). Returns a new array of
// { finding, score, blastRadius, rank } — the input is not mutated. Ties break by
// severity then fingerprint so the order is stable across runs.
export function rankFindings(findings, { blastRadiusFor = () => 0 } = {}) {
  return findings
    .map((finding) => {
      const blastRadius = Number(blastRadiusFor(finding)) || 0;
      return { finding, blastRadius, score: scoreFinding(finding, { blastRadius }) };
    })
    .sort((a, b) =>
      b.score - a.score ||
      severityRank(b.finding.severity) - severityRank(a.finding.severity) ||
      String(a.finding.fingerprint ?? "").localeCompare(String(b.finding.fingerprint ?? "")))
    .map((entry, i) => ({ ...entry, rank: i + 1 }));
}
