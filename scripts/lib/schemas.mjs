// Lightweight runtime validators for the versioned artifact contracts in
// schemas/*.schema.json. The JSON Schema files are the public contract; these
// checks enforce the high-value invariants without adding a heavy validator
// dependency to every command path.

const STATUS = new Set([
  "lead", "candidate", "open", "needs-evidence", "needs-trace",
  "confirmed", "proven", "patched", "remediated", "reviewed", "noise"
]);

const PROOF_STATE = new Set([
  "lead", "candidate", "open", "reachable", "trigger-built",
  "confirmed", "proven", "patch-planned", "patch-validated",
  "remediated", "reviewed", "noise"
]);

const VERIFY_VERDICTS = new Set(["confirmed-exploitable", "not-exploitable", "inconclusive"]);
const POC_VERDICTS = new Set(["exploited", "not-reproduced", "harness-failed-build", "timeout", "error"]);
const FIX_VERDICTS = new Set([
  "validated", "unvalidated-no-harness", "build-failed", "needs-more-evidence",
  "exploit-still-fires", "stops-exploit-breaks-function",
  // Seam for the follow-up agent-driven sibling-caller re-attack (1.3 Option B): a
  // patch that passed the deterministic checks but is awaiting a fresh adversary pass.
  // Maps to no status change (FIX_STATUS leaves it null) — inert until that step ships.
  "validated-pending-reattack"
]);
const RAW_QUERY = new Set(["allow", "require-approval", "deny"]);
const HOOK_ERROR = new Set(["allow", "require-approval", "deny"]);
const NETWORK_INSTALL = new Set(["allow", "approval-only", "deny"]);

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function push(errors, path, message) {
  errors.push(`${path}: ${message}`);
}

function validateEvidenceAnchor(anchor, path, errors) {
  if (!isObject(anchor)) return push(errors, path, "must be an object");
  if (!anchor.filePath || typeof anchor.filePath !== "string") push(errors, `${path}.filePath`, "must be a non-empty string");
  if (anchor.startLine !== undefined && (!Number.isInteger(Number(anchor.startLine)) || Number(anchor.startLine) < 1)) {
    push(errors, `${path}.startLine`, "must be an integer >= 1");
  }
  if (anchor.endLine !== undefined && (!Number.isInteger(Number(anchor.endLine)) || Number(anchor.endLine) < 1)) {
    push(errors, `${path}.endLine`, "must be an integer >= 1");
  }
}

export function validateVerification(value, path = "verification") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  if (!VERIFY_VERDICTS.has(value.verdict)) push(errors, `${path}.verdict`, "invalid verification verdict");
  if (value.confidence === undefined || !Number.isFinite(Number(value.confidence)) || Number(value.confidence) < 0 || Number(value.confidence) > 1) {
    push(errors, `${path}.confidence`, "must be a number between 0 and 1");
  }
  if (!value.verifiedAt || typeof value.verifiedAt !== "string") push(errors, `${path}.verifiedAt`, "must be a timestamp string");
  return errors;
}

export function validatePoc(value, path = "poc") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  if (!Number.isInteger(Number(value.proofLevel)) || Number(value.proofLevel) < 1 || Number(value.proofLevel) > 4) {
    push(errors, `${path}.proofLevel`, "must be an integer 1-4");
  }
  if (!POC_VERDICTS.has(value.proofVerdict)) push(errors, `${path}.proofVerdict`, "invalid PoC verdict");
  if (!value.backend || typeof value.backend !== "string") push(errors, `${path}.backend`, "must be a non-empty string");
  if (!value.provenAt || typeof value.provenAt !== "string") push(errors, `${path}.provenAt`, "must be a timestamp string");
  return errors;
}

export function validateFix(value, path = "fix") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  if (!FIX_VERDICTS.has(value.verdict)) push(errors, `${path}.verdict`, "invalid fix verdict");
  if (!value.patchPath || typeof value.patchPath !== "string") push(errors, `${path}.patchPath`, "must be a non-empty string");
  if (typeof value.applied !== "boolean") push(errors, `${path}.applied`, "must be boolean");
  if (value.verdict === "validated") {
    const v = value.validation ?? {};
    if (v.exploitRegressionPassed !== true) push(errors, `${path}.validation.exploitRegressionPassed`, "must be true for validated fixes");
    if (v.functionalRegressionPassed !== true) push(errors, `${path}.validation.functionalRegressionPassed`, "must be true for validated fixes");
    if (v.semanticRegressionPassed === false) push(errors, `${path}.validation.semanticRegressionPassed`, "must not be false for validated fixes");
    if (v.pocPlusPassed !== true) push(errors, `${path}.validation.pocPlusPassed`, "must be true for validated fixes");
  }
  return errors;
}

export function validateFinding(value, path = "finding") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  for (const key of ["fingerprint", "source", "refId", "title", "severity", "status", "proofState"]) {
    if (!value[key] || typeof value[key] !== "string") push(errors, `${path}.${key}`, "must be a non-empty string");
  }
  if (value.status && !STATUS.has(value.status)) push(errors, `${path}.status`, `invalid status "${value.status}"`);
  if (value.proofState && !PROOF_STATE.has(value.proofState)) push(errors, `${path}.proofState`, `invalid proofState "${value.proofState}"`);
  if (!Array.isArray(value.evidence)) {
    push(errors, `${path}.evidence`, "must be an array");
  } else {
    value.evidence.forEach((anchor, i) => validateEvidenceAnchor(anchor, `${path}.evidence[${i}]`, errors));
  }
  if (value.verification) errors.push(...validateVerification(value.verification, `${path}.verification`));
  if (value.poc) errors.push(...validatePoc(value.poc, `${path}.poc`));
  if (value.fix) errors.push(...validateFix(value.fix, `${path}.fix`));
  return errors;
}

export function validateRulePack(value, path = "rulePack") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  if (value.schemaVersion !== "rule-pack.v1") push(errors, `${path}.schemaVersion`, "must be rule-pack.v1");
  if (!Array.isArray(value.rules)) push(errors, `${path}.rules`, "must be an array");
  for (const [i, rule] of (value.rules ?? []).entries()) {
    if (!rule.ruleId) push(errors, `${path}.rules[${i}].ruleId`, "required");
    if (!rule.engine) push(errors, `${path}.rules[${i}].engine`, "required");
    if (!rule.file) push(errors, `${path}.rules[${i}].file`, "required");
    if (!String(rule.digest ?? "").startsWith("sha256:")) push(errors, `${path}.rules[${i}].digest`, "must be sha256:*");
    if (!isObject(rule.validated)) push(errors, `${path}.rules[${i}].validated`, "required");
  }
  return errors;
}

export function validatePolicy(value, path = "policy") {
  const errors = [];
  if (!isObject(value)) {
    push(errors, path, "must be an object");
    return errors;
  }
  if (!Number.isInteger(Number(value.version))) push(errors, `${path}.version`, "must be an integer");
  if (!value.activeProfile || typeof value.activeProfile !== "string") push(errors, `${path}.activeProfile`, "must be a string");
  if (value.mcp?.rawQuery && !RAW_QUERY.has(value.mcp.rawQuery)) push(errors, `${path}.mcp.rawQuery`, "invalid rawQuery posture");
  if (value.guardrails?.onHookError && !HOOK_ERROR.has(value.guardrails.onHookError)) push(errors, `${path}.guardrails.onHookError`, "invalid hook posture");
  if (value.install?.allowNetworkInstall && !NETWORK_INSTALL.has(value.install.allowNetworkInstall)) {
    push(errors, `${path}.install.allowNetworkInstall`, "invalid install posture");
  }
  return errors;
}

export function assertValid(kind, value) {
  const validators = {
    finding: validateFinding,
    verification: validateVerification,
    poc: validatePoc,
    fix: validateFix,
    rulePack: validateRulePack,
    policy: validatePolicy
  };
  const validate = validators[kind];
  if (!validate) throw new Error(`unknown schema kind: ${kind}`);
  const errors = validate(value);
  if (errors.length) {
    throw new Error(`${kind} schema validation failed:\n- ${errors.join("\n- ")}`);
  }
  return true;
}

export function assertFindingsDocument(doc) {
  if (!isObject(doc)) throw new Error("findings document must be an object");
  if (!Array.isArray(doc.findings)) throw new Error("findings document must contain findings[]");
  const errors = [];
  doc.findings.forEach((finding, i) => errors.push(...validateFinding(finding, `findings[${i}]`)));
  if (errors.length) throw new Error(`findings schema validation failed:\n- ${errors.join("\n- ")}`);
  return true;
}
