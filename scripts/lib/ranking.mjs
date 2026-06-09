// Deterministic priority scoring for findings.
//
// World-class triage is as much about ORDER as detection: an unauthenticated,
// reachable, proven RCE must surface above an admin-only candidate of the same
// CWE. A flat severity label can't express that — "high" alone conflates a
// pre-auth crash with a privilege-gated one. This module combines four
// orthogonal signals already carried on a finding into a single comparable
// score + tier, recomputed on every normalize so it tracks the proof ladder as
// a finding advances. It is pure and side-effect free (host-side determinism
// boundary): no LLM decides priority, the math does.

// 1) Impact if exploited — the severity label, normalized.
const SEVERITY_POINTS = { critical: 40, high: 30, medium: 15, low: 5, info: 0, informational: 0 };

// 2) Confidence the finding is REAL — where it sits on the proof ladder. Resolved
//    rungs (remediated / reviewed / noise / patched) score 0: they're done, not
//    actionable, and must sink below anything still open.
const PROOF_POINTS = {
  proven: 25, confirmed: 18, "trigger-built": 12, reachable: 8,
  "patch-planned": 6, open: 5, candidate: 2, lead: 1,
  "patch-validated": 0, remediated: 0, reviewed: 0, noise: 0
};

// 3) WHO can reach it — attacker class / exposure. Unauthenticated attack surface
//    is the top of the heap; an authenticated or local-only path is strictly less
//    urgent. "unknown" sits mid so an unlabeled finding isn't buried or inflated.
const EXPOSURE_POINTS = {
  unauthenticated: 20, "pre-auth": 20, public: 18, "cross-tenant": 16,
  tenant: 12, authenticated: 10, adjacent: 6, local: 5, internal: 3, unknown: 8
};

const TIERS = [
  { tier: "P0", min: 75 },
  { tier: "P1", min: 55 },
  { tier: "P2", min: 35 },
  { tier: "P3", min: -Infinity }
];

function normalizeKey(value) {
  return String(value ?? "").trim().toLowerCase();
}

// 4) Blast radius / reachability. `reach` is an optional producer-supplied hint:
//   { entryReachable: bool, callerCount: number }. A confirmed entry-point path
//   is the strongest reachability signal (+15); absent that, caller count is a
//   blast-radius proxy, scaled logarithmically so a 2-caller and 2000-caller
//   helper don't sit a thousand points apart. Absent entirely → 0 (neutral).
function reachPoints(reach) {
  if (!reach || typeof reach !== "object") return 0;
  if (reach.entryReachable === true) return 15;
  if (reach.entryReachable === false) return 0;
  const callers = Number(reach.callerCount);
  if (Number.isFinite(callers) && callers > 0) {
    return Math.min(12, Math.round(Math.log2(callers + 1) * 3));
  }
  return 0;
}

// Extract the exposure/attacker-class label from wherever a producer recorded it.
function exposureFor(finding) {
  return normalizeKey(
    finding.exposure ?? finding.attackerClass ?? finding.verification?.attacker ?? "unknown"
  ) || "unknown";
}

// Score a single finding into { score, tier, factors }. `factors` records each
// contribution so the ranking is auditable, not a black box.
export function priorityScore(finding) {
  const severityKey = normalizeKey(finding.severity);
  const exposureKey = exposureFor(finding);
  const factors = {
    severity: SEVERITY_POINTS[severityKey] ?? SEVERITY_POINTS.medium,
    proof: PROOF_POINTS[finding.proofState] ?? PROOF_POINTS.candidate,
    exposure: EXPOSURE_POINTS[exposureKey] ?? EXPOSURE_POINTS.unknown,
    reach: reachPoints(finding.reach)
  };
  const score = factors.severity + factors.proof + factors.exposure + factors.reach;
  const tier = TIERS.find((t) => score >= t.min).tier;
  return { score, tier, factors };
}

// Stable descending sort by priority score; fingerprint breaks ties so the order
// is deterministic across runs. Does not mutate the input array.
export function sortByPriority(findings) {
  return [...findings].sort((a, b) => {
    const sa = a.priority?.score ?? priorityScore(a).score;
    const sb = b.priority?.score ?? priorityScore(b).score;
    if (sb !== sa) return sb - sa;
    return String(a.fingerprint ?? "").localeCompare(String(b.fingerprint ?? ""));
  });
}

export const PRIORITY_TIERS = TIERS.map((t) => t.tier);
