#!/usr/bin/env node
// Deterministic smoke benchmark for the local artifact contracts. It uses a
// temp repo, no network, no external analyzers, and verifies the high-value
// guarantees that should stay stable across releases.

import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { upsertFindings, patchFindings } from "../lib/findings.mjs";
import { storeFor, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { loadPolicy } from "../lib/policy.mjs";
import { exportSarif } from "./export-sarif.mjs";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function runSmoke() {
  const target = mkdtempSync(join(tmpdir(), "kuzushi-bench-"));
  const results = [];
  try {
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "src", "handler.js"), "export function handler(input) { return input }\n");
    const store = storeFor(target);
    mkdirSync(store.root, { recursive: true });

    const findings = upsertFindings(target, [{
      source: "bench",
      refId: "bench:CWE-79",
      title: "Reflected input reaches HTML output",
      severity: "high",
      cwe: "CWE-79",
      verdict: "finding",
      evidence: [{ filePath: "src/handler.js", startLine: 1 }],
      rationale: "Benchmark fixture finding for schema/proof-state validation."
    }]);
    const fp = findings.findings[0].fingerprint;
    assert(findings.schemaVersion === "findings.v1", "findings document schemaVersion missing");
    assert(findings.findings[0].schemaVersion === "finding.v1", "finding schemaVersion missing");
    assert(findings.findings[0].proofState === "open", "open finding proofState mismatch");
    results.push("finding schema + open proofState");

    const verified = patchFindings(target, [{
      fingerprint: fp,
      status: "confirmed",
      verification: {
        schemaVersion: "verification.v1",
        verdict: "confirmed-exploitable",
        confidence: 0.9,
        attackVector: "bench",
        preconditions: [],
        pocSketch: { payload: "<script>alert(1)</script>", howToTrigger: "call handler" },
        pocReady: true,
        gateReview: { verdict: "true-positive", negativePoc: "plain text remains inert", devilsAdvocate: "Escaping could happen later, but no escaping is present in this fixture." },
        verifiedAt: new Date(0).toISOString()
      }
    }]);
    assert(verified.findings[0].proofState === "confirmed", "confirmed proofState mismatch");
    results.push("verification transition");

    const patchPath = join(store.root, "bench.patch");
    writeFileSync(patchPath, "diff --git a/src/handler.js b/src/handler.js\n");
    const patched = patchFindings(target, [{
      fingerprint: fp,
      status: "patched",
      fix: {
        schemaVersion: "fix.v1",
        verdict: "validated",
        patchPath,
        validation: {
          exploitRegressionPassed: true,
          functionalRegressionPassed: true,
          semanticRegressionPassed: true,
          pocPlusPassed: true,
          semanticOracle: "xss"
        },
        applied: false,
        validatedAt: new Date(0).toISOString()
      }
    }]);
    assert(patched.findings[0].proofState === "patch-validated", "patched proofState mismatch");
    results.push("validated fix contract");

    writeJson(store.policyPath, { activeProfile: "ci-locked" });
    const { effective } = loadPolicy(target);
    assert(effective.activeProfile === "ci-locked", "ci profile not active");
    assert(effective.mcp.rawQuery === "deny", "ci rawQuery should deny");
    assert(effective.git.apply === "deny", "ci git apply should deny");
    assert(effective.guardrails.onHookError === "deny", "ci hook errors should deny");
    assert(effective.install.allowNetworkInstall === "deny", "ci install should deny");
    results.push("ci-locked policy profile");

    const sarifResult = exportSarif(target, { all: true });
    assert(existsSync(sarifResult.sarifPath), "SARIF file missing");
    const sarif = JSON.parse(readFileSync(sarifResult.sarifPath, "utf8"));
    assert(sarif.runs[0].properties.kuzushi.policyDigest, "SARIF policy digest missing");
    assert(sarif.runs[0].results[0].properties.proofState === "patch-validated", "SARIF proofState missing");
    results.push("SARIF reproducibility metadata");

    return { ok: true, status: "completed", target, checks: results };
  } finally {
    rmSync(target, { recursive: true, force: true });
  }
}

function main() {
  const result = runSmoke();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
