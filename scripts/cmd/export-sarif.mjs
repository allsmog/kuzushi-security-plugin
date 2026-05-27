#!/usr/bin/env node
// Export .kuzushi/findings.json as SARIF 2.1.0 so findings are consumable by CI,
// code-scanning dashboards, and IDEs. Pure deterministic transform — no agent.
//
// Mapping:
//   - one SARIF `rule` per distinct CWE (fallback: per producer `source`)
//   - one `result` per actionable finding (status open/confirmed/proven, or
//     verdict exploitable/finding); pass --all to include every finding
//   - severity → level: critical/high → error, medium → warning, low/else → note
//   - each finding's evidence anchors → result.locations
//   - fingerprint → partialFingerprints (stable across runs)

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { policyDigest } from "../lib/policy.mjs";
import { provenanceFor } from "../lib/provenance.mjs";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function pluginVersion() {
  try {
    return JSON.parse(readFileSync(join(PLUGIN_ROOT, "package.json"), "utf8")).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function levelFor(severity) {
  const s = String(severity ?? "").toLowerCase();
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note";
}

// Actionable = a real issue worth surfacing in a scanner. Reviewed / noise /
// needs-evidence findings are excluded unless --all.
function isActionable(f) {
  if (["open", "confirmed", "proven"].includes(f.status)) return true;
  return f.verdict === "exploitable" || f.verdict === "finding";
}

function ruleIdFor(f) {
  const cwe = Array.isArray(f.cwe) ? f.cwe[0] : f.cwe;
  if (cwe && String(cwe).trim()) return String(cwe).trim().toUpperCase();
  return `kuzushi/${f.source ?? "finding"}`;
}

function cweTag(ruleId) {
  const m = /^CWE-(\d+)$/i.exec(ruleId);
  return m ? `external/cwe/cwe-${m[1]}` : null;
}

export function exportSarif(target, { all = false } = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const doc = readJsonIfPresent(store.findingsPath);
  if (!doc) throw new Error(`${store.findingsPath} not found — run a producer (e.g. /threat-hunt) first`);
  const provenance = (() => { try { return provenanceFor(resolvedTarget); } catch { return null; } })();

  const findings = (doc.findings ?? []).filter((f) => (all ? true : isActionable(f)));

  // Build the rule table from distinct rule ids.
  const rulesById = new Map();
  for (const f of findings) {
    const id = ruleIdFor(f);
    if (rulesById.has(id)) continue;
    const tag = cweTag(id);
    rulesById.set(id, {
      id,
      name: id.replace(/[^A-Za-z0-9]+/g, ""),
      shortDescription: { text: id.startsWith("CWE-") ? `${id} weakness` : `kuzushi ${f.source ?? ""} finding`.trim() },
      properties: { tags: ["security", ...(tag ? [tag] : [])] }
    });
  }

  const results = findings.map((f) => {
    const id = ruleIdFor(f);
    const anchors = (f.evidence ?? []).filter((a) => a?.filePath);
    const locations = (anchors.length ? anchors : [{ filePath: ".", startLine: 1 }]).map((a) => ({
      physicalLocation: {
        artifactLocation: { uri: String(a.filePath).replace(/^\.\//, "") },
        region: { startLine: Math.max(1, Number(a.startLine ?? 1)) }
      }
    }));
    const rationale = String(f.rationale ?? "").replace(/\s+/g, " ").trim();
    const msg = `${f.title ?? id}${rationale ? ` — ${rationale.slice(0, 600)}` : ""}`;
    return {
      ruleId: id,
      level: levelFor(f.severity),
      message: { text: msg || id },
      locations,
      partialFingerprints: f.fingerprint ? { kuzushiFingerprint: String(f.fingerprint) } : undefined,
      properties: {
        source: f.source, verdict: f.verdict, status: f.status, proofState: f.proofState,
        severity: f.severity, refId: f.refId,
        schemaVersion: f.schemaVersion ?? "finding.v1",
        ...(f.verification ? { verificationVerdict: f.verification.verdict } : {}),
        ...(f.poc ? { proofVerdict: f.poc.proofVerdict } : {}),
        ...(f.fix ? {
          fixVerdict: f.fix.verdict,
          fixApplied: Boolean(f.fix.applied),
          fixPocPlusPassed: Boolean(f.fix.validation?.pocPlusPassed)
        } : {}),
        ...(f.exploitability ? { exploitabilityTier: f.exploitability.tier } : {})
      }
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "kuzushi-security-plugin",
          informationUri: "https://github.com/allsmog/kuzushi-security-plugin",
          version: pluginVersion(),
          rules: [...rulesById.values()]
        }
      },
      results,
      properties: {
        kuzushi: {
          findingsSchemaVersion: doc.schemaVersion ?? "findings.v1",
          policyDigest: policyDigest(resolvedTarget),
          provenance
        }
      }
    }]
  };

  const outPath = join(store.root, "findings.sarif");
  atomicWrite(outPath, `${JSON.stringify(sarif, null, 2)}\n`);
  return {
    ok: true, status: "completed", target: resolvedTarget,
    sarifPath: outPath, resultCount: results.length, ruleCount: rulesById.size,
    includedAll: all, totalFindings: (doc.findings ?? []).length
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("export-sarif --target <path> [--all]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "all"], value: ["target"] });
  if (!flags.target) {
    console.error("export-sarif: --target is required");
    process.exit(1);
  }
  emitResult(exportSarif(flags.target, { all: Boolean(flags.all) }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
