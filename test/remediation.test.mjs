// remediationFor is the deterministic fix-guidance floor every promoted finding
// gets when the agent doesn't supply its own. These pin the CWE normalization,
// the class-level mappings, and the never-empty generic fallback.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { remediationFor, _internals } from "../scripts/lib/remediation.mjs";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { openRun } from "../scripts/lib/artifact-store.mjs";
import { finalizeSystemsHunt } from "../scripts/cmd/systems-hunt-finalize.mjs";

test("maps common CWEs to concrete, class-appropriate fixes", () => {
  assert.match(remediationFor("CWE-89"), /parameteriz|prepared statement/i);
  assert.match(remediationFor("CWE-78"), /execFile|spawn|shell/i);
  assert.match(remediationFor("CWE-918"), /allowlist|private|metadata/i);
  assert.match(remediationFor("CWE-502"), /deserial/i);
  assert.match(remediationFor("CWE-22"), /realpath|base director|\.\./i);
});

test("normalizes CWE forms (CWE-78, 78, cwe_078, array) to the same fix", () => {
  const fix = remediationFor("CWE-78");
  assert.equal(remediationFor("78"), fix);
  assert.equal(remediationFor("cwe_078"), fix);
  assert.equal(remediationFor(78), fix);
  assert.equal(remediationFor(["CWE-78", "CWE-77"]), fix);
});

test("unknown or missing CWE yields the generic floor, never empty", () => {
  assert.equal(remediationFor("CWE-99999"), _internals.GENERIC);
  assert.equal(remediationFor(null), _internals.GENERIC);
  assert.equal(remediationFor(undefined), _internals.GENERIC);
  assert.ok(remediationFor("CWE-89").length > 0);
});

// Integration: a promoter attaches the floor to actionable findings, the agent's
// own remediation wins when supplied, and reviewed verdicts get none.
test("a finalizer attaches remediation to actionable findings (floor + agent override)", () => {
  const t = mkdtempSync(join(tmpdir(), "kz-remediation-"));
  mkdirSync(storeFor(t).root, { recursive: true });
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
  const run = openRun(t, "systems-hunt");
  writeFileSync(join(run.runDir, "draft.systems-hunt.json"), JSON.stringify({ candidates: [
    // actionable, no agent remediation → deterministic CWE-78 floor
    { candidateId: "c1", verdict: "exploitable", cwe: "CWE-78", severity: "high",
      rationale: "x".repeat(240), evidenceAnchors: [{ filePath: "a.c", startLine: 3 }] },
    // actionable, agent remediation present → kept verbatim
    { candidateId: "c2", verdict: "exploitable", cwe: "CWE-787", severity: "high",
      remediation: "bump the buffer to PATH_MAX and bound the copy with the validated length",
      rationale: "y".repeat(240), evidenceAnchors: [{ filePath: "b.c", startLine: 9 }] },
    // reviewed (not actionable) → no remediation attached
    { candidateId: "c3", verdict: "reviewed-no-impact", cwe: "CWE-125",
      rationale: "guarded by a bounds check at b.c:2 " + "z".repeat(240), evidenceAnchors: [{ filePath: "b.c", startLine: 2 }] }
  ] }));
  finalizeSystemsHunt(t, run.runDir);
  const findings = JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings;
  const c1 = findings.find((f) => f.refId === "c1");
  const c2 = findings.find((f) => f.refId === "c2");
  const c3 = findings.find((f) => f.refId === "c3");
  assert.equal(c1.remediation, remediationFor("CWE-78"), "floor applied when agent gave none");
  assert.match(c2.remediation, /PATH_MAX/, "agent remediation kept verbatim");
  assert.equal(c3.remediation, undefined, "non-actionable findings carry no remediation");
});
