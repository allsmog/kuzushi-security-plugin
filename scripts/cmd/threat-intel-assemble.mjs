#!/usr/bin/env node
// Assemble the threat-intel-researcher's stage files (intel-stack-cves.json,
// intel-similar-apps.json, intel-invariants.json) into the canonical
// .kuzushi/threat-intel.json. Filters CVE leads to critical/high, dedupes,
// normalizes invariants, and builds a summary. The invariants[] array is the
// contract /invariant-test (and future modules) consume.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult } from "../lib/artifact-store.mjs";

const SEVERITIES = new Set(["critical", "high"]);

function readJson(path) {
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

function asArray(value, ...keys) {
  if (Array.isArray(value)) return value;
  for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
  return [];
}

function str(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normSeverity(value) {
  const s = str(value).toLowerCase();
  return SEVERITIES.has(s) ? s : null; // drop medium/low/unknown
}

function strList(value) {
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string" && v.trim()).map((v) => v.trim());
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function normLead(raw, source) {
  if (!raw || typeof raw !== "object") return null;
  const severity = normSeverity(raw.severity);
  if (!severity) return null;
  const id = str(raw.id) || str(raw.cve) || str(raw.title);
  if (!id) return null;
  return {
    id,
    cve: str(raw.cve),
    title: str(raw.title) || id,
    severity,
    cwe: str(raw.cwe),
    component: str(raw.component) || str(raw.peer),
    appliesIf: str(raw.applies_if ?? raw.appliesIf),
    currentVersion: str(raw.current_version ?? raw.currentVersion),
    applies: raw.applies === true,
    reference: str(raw.reference ?? raw.url),
    source,
    checksToRun: strList(raw.checks_to_run ?? raw.checksToRun)
  };
}

function normInvariant(raw) {
  if (!raw || typeof raw !== "object") return null;
  const id = str(raw.id);
  const statement = str(raw.statement);
  if (!id || !statement) return null;
  return {
    id,
    statement,
    cwe: str(raw.cwe),
    severity: normSeverity(raw.severity) ?? "high",
    sourceCves: strList(raw.sourceCves ?? raw.source_cves),
    languages: strList(raw.languages),
    sourceSignals: strList(raw.sourceSignals ?? raw.source_signals),
    sinkSignals: strList(raw.sinkSignals ?? raw.sink_signals),
    sanitizerSignals: strList(raw.sanitizerSignals ?? raw.sanitizer_signals),
    taintClass: str(raw.taintClass ?? raw.taint_class),
    appliesTo: strList(raw.appliesTo ?? raw.applies_to),
    checkHint: str(raw.checkHint ?? raw.check_hint)
  };
}

function dedupe(leads) {
  const seen = new Set();
  return leads.filter((l) => {
    const key = `${l.id}|${l.cve}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function assembleThreatIntel(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const stack = readJson(join(resolvedRunDir, "intel-stack-cves.json"));
  const similar = readJson(join(resolvedRunDir, "intel-similar-apps.json"));
  const inv = readJson(join(resolvedRunDir, "intel-invariants.json"));
  if (!stack && !similar && !inv) {
    throw new Error(`no threat-intel stage files in ${resolvedRunDir} (expected intel-stack-cves/similar-apps/invariants.json)`);
  }

  const stackCves = dedupe(asArray(stack, "leads", "cves").map((l) => normLead(l, "stack")).filter(Boolean));
  const similarCves = dedupe(asArray(similar, "leads", "cves").map((l) => normLead(l, "similar-app")).filter(Boolean));
  const invariants = asArray(inv, "invariants").map(normInvariant).filter(Boolean);

  const byCwe = {};
  for (const l of [...stackCves, ...similarCves]) if (l.cwe) byCwe[l.cwe] = (byCwe[l.cwe] ?? 0) + 1;

  const document = {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    target: resolvedTarget,
    domain: str(similar?.domain) || str(stack?.domain) || "",
    stack: stack?.stack ?? null,
    cves: { stack: stackCves, similarApps: similarCves },
    invariants,
    summary: {
      stackCves: stackCves.length,
      similarAppCves: similarCves.length,
      invariants: invariants.length,
      byCwe
    }
  };

  const json = `${JSON.stringify(document, null, 2)}\n`;
  atomicWrite(store.threatIntelPath, json);
  atomicWrite(join(resolvedRunDir, "threat-intel.json"), json);
  atomicWrite(store.threatIntelMdPath, renderMarkdown(document));

  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    threatIntelPath: store.threatIntelPath,
    runDir: resolvedRunDir,
    summary: document.summary
  };
}

function renderMarkdown(doc) {
  const lines = [
    "# Threat Intel", "", `Domain: ${doc.domain || "n/a"}`, "",
    `Stack CVEs (crit/high): ${doc.summary.stackCves} · Similar-app CVEs: ${doc.summary.similarAppCves} · Invariants: ${doc.summary.invariants}`,
    "", "## Stack CVEs"
  ];
  for (const l of doc.cves.stack) lines.push(`- [${l.severity}] ${l.cve || l.id} — ${l.title} (${l.cwe || "CWE n/a"})${l.applies ? " · APPLIES" : ""}`);
  lines.push("", "## Similar-app CVEs");
  for (const l of doc.cves.similarApps) lines.push(`- [${l.severity}] ${l.cve || l.id} — ${l.title} (${l.cwe || "CWE n/a"})`);
  lines.push("", "## Invariants (consumed by /invariant-test)");
  for (const i of doc.invariants) lines.push(`- ${i.id} [${i.severity}/${i.cwe || "CWE n/a"}]: ${i.statement}`);
  return `${lines.join("\n")}\n`;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("threat-intel-assemble --target <path> --run-dir <dir>: assemble research stage files into .kuzushi/threat-intel.json.");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) {
    console.error("threat-intel-assemble: --target and --run-dir are required");
    process.exit(1);
  }
  emitResult(assembleThreatIntel(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
