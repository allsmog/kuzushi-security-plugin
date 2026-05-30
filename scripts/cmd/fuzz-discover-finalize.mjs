#!/usr/bin/env node
// Finalize phase for the discovery-by-execution lane (/fuzz --stage discover, /sweep
// fuzz-discover producer). The discoverer agent crafts malformed inputs and CLAIMS a
// crash; this script is the determinism boundary that decides truth: it re-runs each
// claimed PoC from the draft bytes in a sandbox the finder didn't stage, FORCES the
// sanitizer env, and lets parseSanitizerReport() decide — exactly the proven rule from
// sanitize-pov-finalize. A parsed sanitizer report ⇒ a NEW `proven` finding promoted via
// upsertFindings (source "fuzz-discover", CWE = the sanitizer's exact class); a build
// failure ⇒ harness-failed-build; a clean run ⇒ not-reproduced. NEVER a false proof, and
// no LLM in this step (the abort is the oracle). Unlike /sanitize-pov it requires NO
// pre-existing finding — that's the whole point: discovery independent of static routing.

import { resolve, join } from "node:path";
import { existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, pocVerdictToStatus } from "../lib/findings.mjs";
import { runInSandbox, classifyResult, detectBackend } from "../lib/sandbox.mjs";
import { parseSanitizerReport, SANITIZE_ENV } from "../lib/sanitizers.mjs";
import { crashKey, appendCrash } from "../lib/crashlog.mjs";

function fail(message) { console.error(`fuzz-discover-finalize: ${message}`); process.exit(1); }

const envPrefix = Object.entries(SANITIZE_ENV).map(([k, v]) => `${k}='${v}'`).join(" ");

// Error classes that corrupt memory with attacker influence → critical; other sanitizer
// catches (null-deref, integer overflow surfacing as a trap, leaks) → high.
const CRITICAL_CLASSES = new Set([
  "oob-write", "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
  "dynamic-stack-buffer-overflow", "heap-use-after-free", "use-after-poison", "double-free"
]);

// Where the bug is: the agent's target-relative anchor wins (it reasoned about the source);
// the sanitizer frame only sharpens/﻿back-stops it. Always returns at least one anchor so the
// promoted finding validates.
function discoveryEvidence(discovery, report) {
  const ev = Array.isArray(discovery.evidence) && discovery.evidence.length ? discovery.evidence : null;
  if (ev) return ev;
  const frame = report?.frame0;
  if (frame?.file) return [{ filePath: String(frame.file), ...(frame.line ? { startLine: Number(frame.line) } : {}) }];
  return [{ filePath: discovery.subsystem ? String(discovery.subsystem) : "discovered-by-execution" }];
}

// PURE: map a sanitizer-confirmed discovery to a NEW finding record. The CWE + crash class
// come from the report (ground truth), not from the agent's claim. Returns null when there
// is no sanitizer report (nothing proven ⇒ nothing promoted). Exported so the promotion
// spine can be unit-tested from a CAPTURED report with no compiler in the loop.
export function buildDiscoveryFinding({ discovery, report, proofLevel = 4, backend, durationMs = null, harnessDir = null, runCommand = null, logPath = null, provenAt }) {
  if (!report) return null;
  const key = crashKey(report, discovery.title ?? "discovered");
  const evidence = discoveryEvidence(discovery, report);
  const severity = CRITICAL_CLASSES.has(report.errorClass) ? "critical" : "high";
  return {
    source: "fuzz-discover",
    refId: `fuzz-discover:${key}`,
    title: discovery.title ? String(discovery.title) : `${report.errorClass} reached by execution`,
    severity,
    cwe: report.cwe,
    status: "proven",
    evidence,
    rationale: `Found by discovery-by-execution: a crafted input drove ${report.tool} to report ${report.errorClass} (${report.cwe})${report.frame0?.file ? ` at ${report.frame0.file}:${report.frame0.line ?? "?"}` : report.frame0?.symbol ? ` in ${report.frame0.symbol}` : ""}. The sanitizer abort is the verdict; re-run the PoC bytes to reproduce.`,
    nextChecks: ["Minimize the crashing input.", "Assess exploitability (/mem-exploitability).", "Generate a patch (/fix) and re-attack it."],
    poc: {
      schemaVersion: "poc.v1",
      proofLevel,
      proofVerdict: "exploited",
      backend: backend ?? "unknown",
      durationMs,
      ...(harnessDir ? { harnessDir } : {}),
      ...(runCommand ? { runCommand } : {}),
      ...(logPath ? { logPath } : {}),
      provenAt: provenAt ?? new Date().toISOString(),
      sanitizer: { tool: report.tool, errorClass: report.errorClass, cwe: report.cwe, frame0: report.frame0 ?? null }
    },
    _crashKey: key
  };
}

async function runOne(discovery, runDir, backendInfo, trustLocal, idx) {
  const harnessDir = join(runDir, "harness", `discovery-${idx}`);
  mkdirSync(harnessDir, { recursive: true });
  for (const f of discovery.harnessFiles ?? []) {
    if (!f?.name || String(f.name).includes("..")) continue;
    const p = join(harnessDir, f.name);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, String(f.content ?? ""));
  }
  const runCommand = `${envPrefix} ${discovery.buildRunCommand}`;
  const result = await runInSandbox({
    backend: backendInfo.backend, language: discovery.language ?? "c",
    harnessDir, runCommand, timeoutMs: Number(discovery.timeoutMs ?? 180000), trustLocal
  });
  const out = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const report = parseSanitizerReport(out);
  const classified = classifyResult(result);
  // The sanitizer report is the oracle and outranks the generic classifier — UNLESS the
  // harness never built (a build failure must never read as a proof).
  let proofVerdict = classified.proofVerdict;
  let proofLevel = classified.proofLevel;
  if (report && classified.proofVerdict !== "harness-failed-build") { proofVerdict = "exploited"; proofLevel = 4; }
  const logPath = join(harnessDir, "run.log");
  writeFileSync(logPath, out);
  return { report, proofVerdict, proofLevel, backend: result.backend ?? backendInfo.backend, durationMs: result.durationMs ?? null, harnessDir, runCommand, logPath, skipped: Boolean(result.skipped), reason: result.reason ?? null };
}

export async function finalizeFuzzDiscover(target, runDir, input = {}) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.fuzz-discover.json");
  if (!existsSync(draftPath)) fail(`no draft.fuzz-discover.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.fuzz-discover.json is not valid JSON"); }
  const discoveries = Array.isArray(draft.discoveries) ? draft.discoveries : null;
  if (!discoveries || !discoveries.length) fail("draft must have discoveries[] (each { title, language, harnessFiles[], buildRunCommand })");
  for (const d of discoveries) {
    if (!d.buildRunCommand) fail("each discovery needs a buildRunCommand that compiles WITH -fsanitize and runs the crafted input");
  }

  const override = input.backend ?? draft.backend;
  const backendInfo = override ? { backend: override, reason: "explicit override" } : detectBackend();
  const trustLocal = Boolean(input.trustLocal ?? draft.trustLocal);

  const provenAt = new Date().toISOString();
  const results = [];
  const toPromote = [];
  for (let i = 0; i < discoveries.length; i += 1) {
    const d = discoveries[i];
    const r = await runOne(d, resolvedRunDir, backendInfo, trustLocal, i);
    let promoted = null;
    let duplicate = false;
    if (r.proofVerdict === "exploited" && r.report) {
      const finding = buildDiscoveryFinding({
        discovery: d, report: r.report, proofLevel: r.proofLevel, backend: r.backend,
        durationMs: r.durationMs, harnessDir: r.harnessDir, runCommand: r.runCommand, logPath: r.logPath, provenAt
      });
      const log = appendCrash(resolvedTarget, { crashKey: finding._crashKey, title: finding.title, cwe: finding.cwe });
      duplicate = log.duplicate;
      const { _crashKey, ...clean } = finding;
      toPromote.push(clean);                 // upsert dedups exact repeats by fingerprint anyway
      promoted = { refId: clean.refId, cwe: clean.cwe, severity: clean.severity, crashKey: _crashKey, duplicate };
    }
    results.push({
      title: d.title ?? null, proofVerdict: r.proofVerdict, proofLevel: r.proofLevel,
      backend: r.backend, durationMs: r.durationMs, harnessDir: r.harnessDir, runCommand: r.runCommand,
      logPath: r.logPath, sanitizer: r.report, skipped: r.skipped, reason: r.reason, promoted, duplicate
    });
  }

  let findingsDoc = null;
  if (toPromote.length) findingsDoc = upsertFindings(resolvedTarget, toPromote);

  const doc = { schemaVersion: "fuzz-discover.v1", generatedAt: provenAt, target: resolvedTarget, backend: backendInfo.backend, results };
  atomicWrite(store.fuzzDiscoverPath, `${JSON.stringify(doc, null, 2)}\n`);
  atomicWrite(join(resolvedRunDir, "fuzz-discover.json"), `${JSON.stringify(doc, null, 2)}\n`);

  const proven = results.filter((r) => r.proofVerdict === "exploited");
  const run = openRun(resolvedTarget, "fuzz-discover-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget, backend: backendInfo.backend,
    discoveryCount: discoveries.length,
    provenCount: proven.length,
    promotedCount: toPromote.length,
    proven: proven.map((r) => ({ title: r.title, cwe: r.sanitizer?.cwe ?? null, errorClass: r.sanitizer?.errorClass ?? null, refId: r.promoted?.refId ?? null })),
    verdicts: results.map((r) => ({ title: r.title, proofVerdict: r.proofVerdict, sanitizer: r.sanitizer?.errorClass ?? null })),
    fuzzDiscoverPath: store.fuzzDiscoverPath,
    findingsSummary: findingsDoc?.summary ?? null
  };
  run.finalize(result);
  return result;
}

async function main() {
  if (process.argv.includes("--help")) {
    console.log("fuzz-discover-finalize --target <path> --run-dir <dir> [--input '{\"trustLocal\":true}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir", "input", "input-file"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(await finalizeFuzzDiscover(flags.target, flags["run-dir"], loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
