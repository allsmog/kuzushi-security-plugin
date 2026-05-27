#!/usr/bin/env node
// Apply a validated patch to the working tree — the ONLY script in /fix that
// writes source, and the action the native Allow/Deny prompt gates. It is invoked
// explicitly, one fingerprint at a time, and HARD-REFUSES anything whose fix
// verdict is not "validated" (so even an erroneous call can't apply an
// unvalidated patch). `git apply --check` first guards against working-tree drift
// since validation. On success it advances the finding to status "remediated"
// and returns the rollback command.

import { resolve, join } from "node:path";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { patchFindings } from "../lib/findings.mjs";

function fail(message) {
  console.error(`fix-apply: ${message}`);
  process.exit(1);
}

export function applyFix(target, fingerprint, { checkOnly = false } = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const fixDoc = readJsonIfPresent(store.fixPath);
  if (!fixDoc) fail(`${store.fixPath} not found — run /fix first`);

  const entry = (fixDoc.results ?? []).find((r) => r.findingFingerprint === fingerprint);
  if (!entry) fail(`no fix result for fingerprint ${fingerprint}`);

  // Hard gate: only a PoC⁺-validated patch may touch the working tree.
  if (entry.verdict !== "validated") {
    fail(`refusing to apply: fix verdict for ${fingerprint} is "${entry.verdict}", not "validated". Only validated patches can be applied.`);
  }
  const patchPath = entry.patchPath;
  if (!patchPath || !existsSync(patchPath)) fail(`patch file missing: ${patchPath}`);

  // Drift guard: the patch must still apply cleanly to the current tree.
  const check = spawnSync("git", ["apply", "--check", patchPath], { cwd: resolvedTarget, encoding: "utf8" });
  if (check.status !== 0) {
    fail(`git apply --check failed — the working tree changed since validation. Re-run /fix. Detail: ${(check.stderr ?? "").slice(0, 300)}`);
  }
  if (checkOnly) {
    return { ok: true, status: "check-passed", target: resolvedTarget, fingerprint, patchPath };
  }

  const apply = spawnSync("git", ["apply", patchPath], { cwd: resolvedTarget, encoding: "utf8" });
  if (apply.status !== 0) {
    fail(`git apply failed: ${(apply.stderr ?? "").slice(0, 300)}`);
  }

  const appliedAt = new Date().toISOString();
  const updated = patchFindings(resolvedTarget, [{
    fingerprint,
    status: "remediated",
    fix: {
      verdict: entry.verdict,
      patchPath: entry.patchPath,
      harnessLinkage: entry.harnessLinkage ?? null,
      stops: entry.stops ?? null,
      functional: entry.functional ?? null,
      validatedAt: fixDoc.generatedAt ?? null,
      applied: true,
      appliedAt
    }
  }]);

  return {
    ok: true,
    status: "applied",
    target: resolvedTarget,
    fingerprint,
    patchPath,
    rollback: `git apply -R "${patchPath}"   (run from ${resolvedTarget})`,
    findingsSummary: updated.summary
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("fix-apply --target <path> --fingerprint <fp> [--check-only]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "check-only"], value: ["target", "fingerprint"] });
  if (!flags.target || !flags.fingerprint) fail("--target and --fingerprint are required");
  emitResult(applyFix(flags.target, flags.fingerprint, { checkOnly: Boolean(flags["check-only"]) }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
