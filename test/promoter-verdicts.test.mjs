// Closed-verdict enforcement for the remaining finding-promoters — the gate that
// stops an agent's out-of-set verdict from being promoted into findings.json.
// These finalizers (several added by fast-moving parallel work: authz, iac,
// traffic-map) were untested; an unguarded verdict set is exactly how a producer
// silently drifts. Each case writes a draft with a bogus verdict and asserts the
// finalizer REJECTS it (non-zero exit) rather than promoting or crashing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openRun, storeFor } from "../scripts/lib/artifact-store.mjs";

const cmd = (name) => new URL(`../scripts/cmd/${name}.mjs`, import.meta.url).pathname;

// A candidate carrying every id-field name the various finalizers use, an
// out-of-set verdict, and enough rationale/anchors to get past pre-verdict
// checks so the VERDICT gate is what fires.
const bogusCandidate = {
  id: "x1", candidateId: "x1", threatId: "x1", findingFingerprint: "x1",
  verdict: "definitely-not-a-valid-verdict",
  rationale: "x".repeat(240),
  evidence: [{ filePath: "a.js", startLine: 1 }],
  evidenceAnchors: [{ filePath: "a.js", startLine: 1 }],
  cwe: "CWE-89", severity: "high", title: "t", category: "dangerous-defaults"
};

const cases = [
  { script: "authz-finalize", draft: "draft.authz.json", kind: "authz" },
  { script: "iac-finalize", draft: "draft.iac.json", kind: "iac" },
  { script: "traffic-map-finalize", draft: "draft.traffic-map.json", kind: "traffic-map" },
  { script: "sast-finalize", draft: "draft.sast.json", kind: "sast" },
  { script: "sharp-edges-finalize", draft: "draft.sharp-edges.json", kind: "sharp-edges" },
  { script: "crypto-review-finalize", draft: "draft.crypto-review.json", kind: "crypto-review" },
  { script: "diff-review-finalize", draft: "draft.diff-review.json", kind: "diff-review" },
  { script: "variant-hunt-finalize", draft: "draft.variant-hunt.json", kind: "variant-hunt" }
];

for (const c of cases) {
  test(`${c.script} rejects a bogus-verdict candidate cleanly (no crash, no promotion)`, () => {
    const t = mkdtempSync(join(tmpdir(), `kz-${c.kind}-`));
    const run = openRun(t, c.kind);
    // Provide the candidate under both the common array keys so whichever the
    // finalizer reads, it sees a bogus verdict; if it reads neither, it rejects
    // on the missing array — either way it must reject cleanly.
    writeFileSync(join(run.runDir, c.draft), JSON.stringify({ candidates: [bogusCandidate], findings: [bogusCandidate] }));
    const r = spawnSync("node", [cmd(c.script), "--target", t, "--run-dir", run.runDir], { encoding: "utf8" });
    const out = `${r.stderr}${r.stdout}`;
    assert.notEqual(r.status, 0, `${c.script} must reject (got exit 0): ${out.slice(0, 200)}`);
    // A controlled rejection prints a one-line "<script>: <reason>" via fail(),
    // never an unhandled exception with a JS stack frame.
    assert.doesNotMatch(out, /\n\s+at .+:\d+:\d+/, `${c.script} rejected via an unhandled crash, not a clean fail(): ${out.slice(0, 300)}`);
    // And nothing got promoted with the bogus verdict.
    const fp = storeFor(t).findingsPath;
    if (existsSync(fp)) assert.doesNotMatch(readFileSync(fp, "utf8"), /definitely-not-a-valid-verdict/, `${c.script} promoted a bogus-verdict finding`);
  });
}
