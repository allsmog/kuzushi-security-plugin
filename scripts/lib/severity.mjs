// Deterministic severity derivation — kuzushi's answer to "how bad is this, really?"
//
// WHY this lives in a lib (not an agent prompt): per the determinism boundary
// (CLAUDE.md), anything that must be trustworthy goes in code where it can't be
// reasoned around. Severity is exactly that — an agent left to assert severity
// inflates it ("alert fatigue"); the scanner's claimed label is not load-bearing.
//
// The rule is modeled on the precondition × access-level table used by mature
// triage flows: severity is a function of (a) how many preconditions must hold
// for exploitation and (b) the minimum access an attacker needs. Each column is
// scored independently and we take the LOWER — a bug with zero preconditions but
// reachable only locally is still LOW. A threat-model match may raise the result
// by at most ONE step (never two, never to a class the table can't reach).
//
// deriveSeverity() is the trustworthy gate; judgeClaimedSeverity() is a separate,
// advisory inflation signal ("is the agent's claimed severity comparable to the
// derived one, or is it alert-fatigue noise?"). Verification ("is it real") and
// severity ("how bad") are independent judgments — proven-real must not auto-inflate.

export const SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"];
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// The derivation table tops out at HIGH — CRITICAL is reserved for downstream
// signals the table can't see (empirical proof, chain escalation, memory-corruption
// classes), never assigned from preconditions/access alone.
const DERIVE_CEILING = "high";

// Precondition COUNT → severity column. 0 → HIGH, 1-2 → MEDIUM, 3+ → LOW.
function preconditionSeverity(count) {
  if (count <= 0) return "high";
  if (count <= 2) return "medium";
  return "low";
}

// Minimum ACCESS the attacker needs → severity column. Synonyms are normalized so
// agents can write the access level the natural way ("unauthenticated remote",
// "remote-unauth", "local-only", …) without the gate caring about spelling.
const ACCESS_SEVERITY = {
  "unauthenticated-remote": "high",
  "unauthenticated": "high",
  "unauth": "high",
  "remote": "high",
  "remote-unauth": "high",
  "network": "high",
  "anonymous": "high",
  "public": "high",
  "authenticated": "medium",
  "authenticated-remote": "medium",
  "authed": "medium",
  "user": "medium",
  "tenant": "medium",
  "adjacent": "medium",
  "adjacent-network": "medium",
  "local": "low",
  "local-only": "low",
  "localhost": "low",
  "physical": "low",
  "admin": "low",
  "operator": "low",
  "privileged": "low"
};

export function normalizeAccessLevel(accessLevel) {
  const key = String(accessLevel ?? "").toLowerCase().trim().replace(/\s+/g, "-");
  return ACCESS_SEVERITY[key] ? key : null;
}

function accessSeverity(accessLevel) {
  const key = normalizeAccessLevel(accessLevel);
  return key ? ACCESS_SEVERITY[key] : null;
}

// preconditions may be an array (the natural shape — "enumerate EVERY precondition")
// or a bare count. Returns null when nothing usable was supplied so the caller knows
// the column is absent rather than "zero" (zero would wrongly imply HIGH).
function preconditionCount(preconditions) {
  if (Array.isArray(preconditions)) return preconditions.filter((p) => String(p ?? "").trim()).length;
  if (typeof preconditions === "number" && Number.isFinite(preconditions)) return Math.max(0, Math.trunc(preconditions));
  return null;
}

export function normalizeClaimed(claimed) {
  const key = String(claimed ?? "").toLowerCase().trim();
  return RANK[key] !== undefined ? key : null;
}

const lower = (a, b) => (RANK[a] <= RANK[b] ? a : b);

function raiseOneStep(severity) {
  const next = Math.min(RANK[severity] + 1, RANK[DERIVE_CEILING]);
  return SEVERITY_LEVELS[next];
}

// Derive a severity from preconditions + access level. Returns
//   { severity, derived, boosted, basis, reason }
// `derived:false` means neither column was usable, so we fell back to the agent's
// claimed severity (advisory) — the caller can record that the gate didn't fire.
export function deriveSeverity(input = {}) {
  const { accessLevel, threatModelMatch = false, claimed } = input;
  const count = preconditionCount(input.preconditions);
  const fromPre = count === null ? null : preconditionSeverity(count);
  const fromAccess = accessSeverity(accessLevel);

  const columns = [fromPre, fromAccess].filter(Boolean);
  if (columns.length === 0) {
    return {
      severity: normalizeClaimed(claimed) ?? "medium",
      derived: false,
      boosted: false,
      basis: { preconditionCount: count, accessLevel: normalizeAccessLevel(accessLevel) },
      reason: "no usable preconditions or accessLevel; fell back to claimed severity"
    };
  }

  // Take the LOWER of whatever columns we have (a missing column never lowers).
  let severity = columns.reduce(lower);
  let boosted = false;
  if (threatModelMatch) {
    const raised = raiseOneStep(severity);
    boosted = raised !== severity;
    severity = raised;
  }

  return {
    severity,
    derived: true,
    boosted,
    basis: {
      preconditionCount: count,
      accessLevel: normalizeAccessLevel(accessLevel),
      fromPreconditions: fromPre,
      fromAccess
    },
    reason:
      `lower(${fromPre ?? "—"}, ${fromAccess ?? "—"}) = ${columns.reduce(lower)}` +
      (boosted ? ` then +1 step (threat-model match) → ${severity}` : "")
  };
}

// Advisory inflation signal: compare the agent's CLAIMED severity against the
// DERIVED one. Positive = claimed is accurate or understated (trustworthy);
// negative = claimed is inflated above what preconditions/access justify (the
// alert-fatigue failure mode). Score in [-5, +5]. This NEVER changes the stored
// severity — it's a separate number a reviewer / report can surface.
export function judgeClaimedSeverity({ claimed, derived }) {
  const c = RANK[normalizeClaimed(claimed)];
  const d = RANK[normalizeClaimed(derived) ?? derived];
  if (c === undefined || d === undefined) {
    return { score: 0, delta: null, note: "insufficient info to judge claimed severity" };
  }
  const delta = c - d; // >0 means claimed is HIGHER than derived (inflation)
  let score;
  if (delta <= -1) score = 5; // understated — strictly safe
  else if (delta === 0) score = 4; // accurate
  else if (delta === 1) score = 0; // one step high — borderline
  else if (delta === 2) score = -3; // two steps — inflated
  else score = -5; // three+ steps — alert-fatigue noise
  const note =
    delta <= 0
      ? "claimed severity is justified or understated"
      : delta === 1
        ? "claimed severity is one step above derived — borderline"
        : "claimed severity is inflated above what preconditions/access justify";
  return { score, delta, note };
}

// Convenience for finalize promotion. Given an agent candidate `c` carrying any of
// { preconditions, accessLevel, threatModelMatch, severity }, return the finding
// fields { severity, severityBasis? } with severity DERIVED (the claim is advisory).
// Backward-compatible: a candidate with none of the inputs falls back to its claimed
// severity and omits severityBasis (so older drafts behave exactly as before).
export function severityFieldsFor(c) {
  const sev = deriveSeverity({
    preconditions: c.preconditions,
    accessLevel: c.accessLevel,
    threatModelMatch: c.threatModelMatch,
    claimed: c.severity
  });
  return {
    severity: sev.severity,
    ...(sev.derived
      ? { severityBasis: { ...sev.basis, boosted: sev.boosted, claimedJudgment: judgeClaimedSeverity({ claimed: c.severity, derived: sev.severity }) } }
      : {})
  };
}

export { RANK as SEVERITY_RANK };
