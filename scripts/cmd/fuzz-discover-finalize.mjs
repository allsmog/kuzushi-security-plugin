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

import { resolve, join, isAbsolute } from "node:path";
import { existsSync, readFileSync, mkdirSync, writeFileSync, cpSync } from "node:fs";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, pocVerdictToStatus } from "../lib/findings.mjs";
import { runInSandbox, classifyResult, detectBackend } from "../lib/sandbox.mjs";
import { parseSanitizerReport, SANITIZE_ENV } from "../lib/sanitizers.mjs";
import { crashKey, appendCrash } from "../lib/crashlog.mjs";

function fail(message) { console.error(`fuzz-discover-finalize: ${message}`); process.exit(1); }

const envPrefix = Object.entries(SANITIZE_ENV).map(([k, v]) => `${k}='${v}'`).join(" ");

// --- Promotion gates (the eval forensics: the lane "proved" a benign signed-overflow in a
// vendored client RESP parser, reached only by a standalone leaf harness). Two deterministic
// gates, enforced here so the agent can't reason around them. ---------------------------------

// Source files named in the sanitizer backtrace.
function crashFrameFiles(out) {
  const files = [];
  const re = /#\d+[^\n]*?([A-Za-z0-9_./\-+]+\.(?:c|cc|cpp|cxx|h|hpp|hh|m|mm|rs)):\d+/gi;
  let m;
  while ((m = re.exec(String(out ?? ""))) !== null) files.push(m[1]);
  return files;
}
// Frames that are NOT the target's own first-party source: vendored deps, test/example code,
// or harness/stub scaffolding. A crash whose frames are ALL off-target was not reached through
// the real entry point (it's the leaf-harness retreat) — reject it. NOTE: a bug in an embedded
// interpreter reached via the real entry (e.g. lua via an EVAL command) still has a first-party
// frame on the stack (the command handler), so it passes — only vendored-ONLY crashes fail.
const OFF_TARGET = /(?:^|\/)(?:deps|vendor|third[_-]?party|external|node_modules|contrib|examples?|tests?)\/|harness|(?:^|[_/])stub|fuzz[_-]?driver|(?:^|\/)mock|conftest|_test\.|(?:^|\/)test_/i;
export function crashOffTargetOnly(out) {
  const files = crashFrameFiles(out);
  return files.length > 0 && files.every((f) => OFF_TARGET.test(f));
}
// Weak-tier sanitizer classes: undefined behavior with no demonstrated memory-corruption
// consequence (a bare signed/unsigned overflow, a bad shift). UB, frequently benign. A REAL
// integer-overflow that corrupts memory surfaces instead as an OOB-write / deadly-signal
// (parseSanitizerReport returns that stronger class first), so this only catches the benign tier.
export const WEAK_TIER = new Set(["integer-overflow", "bad-shift", "undefined-behavior", "misaligned-access", "div-by-zero"]);

// Invariant-oracle proof (non-crash classes: prototype pollution, etc.). A framework-owned
// oracle harness drives standard payloads and, on a real invariant violation, prints this
// marker. The agent writes NO code that runs in the oracle, so the marker is ungameable — the
// finalize trusts it exactly as it trusts a sanitizer report. Shape mirrors parseSanitizerReport.
const ORACLE_DIR = resolve(import.meta.dirname ?? ".", "../lib/oracle-harness");
const ORACLE_HARNESS = { "prototype-pollution": "proto-pollution.mjs" };
export function parseOracleMarker(out) {
  const m = /KUZUSHI-ORACLE:\s*(CWE-\d+)\s+([a-z0-9-]+)\b([^\n]*)/i.exec(String(out ?? ""));
  if (!m) return null;
  return { tool: "invariant-oracle", errorClass: m[2], cwe: m[1], summary: `${m[2]}${m[3] ?? ""}`.trim().slice(0, 200), frame0: null };
}

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

async function runOne(discovery, runDir, backendInfo, trustLocal, idx, resolvedTarget) {
  const harnessDir = join(runDir, "harness", `discovery-${idx}`);
  mkdirSync(harnessDir, { recursive: true });

  // Invariant-oracle path (non-crash classes). The agent only DECLARED a target + input shape;
  // the FRAMEWORK oracle harness (copied in here, not from the draft) drives standard payloads
  // and checks the invariant, so the proof can't be faked. No sanitizer build, and the
  // first-party/weak-tier gates don't apply (this isn't a memory crash) — the marker IS the proof.
  if (discovery.oracle && ORACLE_HARNESS[discovery.oracle]) {
    const harnessName = ORACLE_HARNESS[discovery.oracle];
    cpSync(join(ORACLE_DIR, harnessName), join(harnessDir, harnessName));
    const tm = String(discovery.targetModule ?? "");
    const absTarget = tm && isAbsolute(tm) ? tm : join(resolvedTarget ?? ".", tm || "index.js");
    const runCommand = `node ${harnessName} '${absTarget}' '${String(discovery.inputShape ?? "auto")}'`;
    const result = await runInSandbox({ backend: backendInfo.backend, language: "javascript", harnessDir, runCommand, timeoutMs: Number(discovery.timeoutMs ?? 60000), trustLocal });
    const out = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const report = parseOracleMarker(out);
    const logPath = join(harnessDir, "run.log");
    writeFileSync(logPath, out);
    return { report, proofVerdict: report ? "exploited" : "not-reproduced", proofLevel: report ? 3 : 0, gate: null, backend: result.backend ?? backendInfo.backend, durationMs: result.durationMs ?? null, harnessDir, runCommand, logPath, skipped: Boolean(result.skipped), reason: result.reason ?? null };
  }

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
  // harness never built (a build failure must never read as a proof), the crash is reachable
  // only through vendored/stub/harness frames (the leaf-harness retreat), or it's a weak-tier
  // UB with no memory consequence. The last two are recorded, never promoted.
  let proofVerdict = classified.proofVerdict;
  let proofLevel = classified.proofLevel;
  let gate = null;
  if (report && classified.proofVerdict !== "harness-failed-build") {
    if (crashOffTargetOnly(out)) { proofVerdict = "off-target"; gate = "crash frames are all vendored/stub/harness — not reachable from a real entry point"; }
    else if (WEAK_TIER.has(report.errorClass)) { proofVerdict = "weak-tier"; gate = `${report.errorClass}: undefined behavior with no memory-corruption consequence — candidate, not proven`; }
    else { proofVerdict = "exploited"; proofLevel = 4; }
  }
  const logPath = join(harnessDir, "run.log");
  writeFileSync(logPath, out);
  return { report, proofVerdict, proofLevel, gate, backend: result.backend ?? backendInfo.backend, durationMs: result.durationMs ?? null, harnessDir, runCommand, logPath, skipped: Boolean(result.skipped), reason: result.reason ?? null };
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
    // An invariant-oracle discovery (non-crash class) declares a target, not a build command —
    // the framework oracle supplies the run. A memory-class discovery needs its buildRunCommand.
    if (d.oracle && ORACLE_HARNESS[d.oracle]) { if (!d.targetModule) fail("an oracle discovery needs a targetModule"); continue; }
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
    const r = await runOne(d, resolvedRunDir, backendInfo, trustLocal, i, resolvedTarget);
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
      title: d.title ?? null, proofVerdict: r.proofVerdict, proofLevel: r.proofLevel, gate: r.gate ?? null,
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
