#!/usr/bin/env node
// Prepare phase for /chain (proactive attack-path engine). Gathers the live
// findings AND the scaffolding to SEARCH for attack paths — not just compose
// confirmed findings:
//   • the crown-jewel ASSETS an attacker wants (threat-model DFD data stores /
//     services, deep-context data stores) — the path destinations;
//   • the attacker-reachable ENTRY POINTS (code-graph / deep-context / x-ray) —
//     the path origins;
//   • a compact REACHABILITY summary (top code-graph symbols by caller count).
// The chain-finder uses these to find ordered entry→…→asset paths where each
// step is enabled by a finding — composing even SUB-THRESHOLD primitives
// (candidate / lead) into a critical chain. Pure read-only; no baked-in heuristics.

import { resolve, join } from "node:path";
import { parseFlags, loadInput } from "../lib/argv.mjs";
import { storeFor, openRun, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";

// Findings worth considering as chain members. Reviewed/noise/remediated are
// excluded; everything else — including sub-threshold lead / candidate primitives —
// can be a link in a path, because the whole point is that individually-low bugs
// compose into a critical chain.
const CHAINABLE_STATUS = new Set(["lead", "candidate", "open", "confirmed", "proven", "needs-evidence", "needs-trace", "patched"]);

const norm = (p) => String(p ?? "").replace(/^\.\//, "");
const ASSET_RE = /database|data[_\s-]?store|datastore|\bstore\b|\bqueue\b|secret|credential|vault|bucket|\bs3\b|keystore|wallet|ledger|account|session\s*store/i;

// Crown-jewel assets = the path destinations. From the threat-model DFD nodes
// (databases/services/stores) and deep-context data stores. Best-effort; empty
// when neither artifact exists (the chainer then composes findings without a
// destination hint).
function assetsFrom(store) {
  const out = [];
  const tm = readJsonIfPresent(store.threatModelPath);
  for (const n of tm?.dfd?.nodes ?? []) {
    const type = String(n.type ?? "").toLowerCase();
    const name = String(n.name ?? n.id ?? "");
    if (/database|data_store|datastore|store|queue/.test(type) || ASSET_RE.test(name)) {
      out.push({ name: name || n.id, type: n.type ?? "data_store", from: "threat-model" });
    }
  }
  const dc = readJsonIfPresent(store.deepContextPath);
  for (const d of dc?.dataStores ?? []) {
    out.push({
      name: d.name ?? d.id ?? "data store", type: "data_store", from: "deep-context",
      evidence: d.filePath ? [{ filePath: norm(d.filePath), startLine: d.startLine ?? 1 }] : []
    });
  }
  const seen = new Set();
  return out.filter((a) => {
    const k = String(a.name).toLowerCase();
    if (!a.name || seen.has(k)) return false;
    seen.add(k); return true;
  }).slice(0, 25);
}

// Attacker-reachable entry points = the path origins. From code-graph entry
// points, deep-context entry points, and the x-ray entry-points cache.
function entryPointsFrom(store) {
  const out = [];
  const cg = readJsonIfPresent(store.codeGraphPath);
  for (const e of cg?.entryPoints ?? []) out.push({ filePath: norm(e.filePath), line: e.line, kind: e.kind, boundary: e.boundary, from: "code-graph" });
  const dc = readJsonIfPresent(store.deepContextPath);
  for (const e of dc?.entryPoints ?? []) if (e?.filePath) out.push({ filePath: norm(e.filePath), kind: e.kind ?? "entry", from: "deep-context" });
  const xr = readJsonIfPresent(`${store.xRayDir}/entry-points.json`);
  for (const e of Array.isArray(xr) ? xr : []) if (e?.filePath) out.push({ filePath: norm(e.filePath), kind: e.kind ?? e.id, boundary: e.boundary, from: "x-ray" });
  const seen = new Set();
  return out.filter((e) => {
    if (!e.filePath) return false;
    const k = `${e.filePath}|${e.kind ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  }).slice(0, 40);
}

// Compact reachability summary so the agent can reason about what reaches what
// without a full CPG: the highest-blast-radius symbols + entry-point count.
function reachabilityFrom(store) {
  const cg = readJsonIfPresent(store.codeGraphPath);
  if (!Array.isArray(cg?.symbols)) return null;
  return {
    topSymbols: cg.symbols.slice(0, 20).map((s) => ({ name: s.name, file: norm(s.file), callerCount: s.callerCount ?? 0 })),
    entryPointCount: (cg.entryPoints ?? []).length
  };
}

export function prepareChain(target, input = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const findingsDoc = readJsonIfPresent(store.findingsPath);
  if (!findingsDoc) throw new Error(`${store.findingsPath} not found — run a hunt first (/threat-hunt, /taint-analysis, …)`);

  const findings = (findingsDoc.findings ?? []).filter((f) => CHAINABLE_STATUS.has(f.status));
  if (findings.length < 2) {
    throw new Error(`need at least 2 live findings to chain (have ${findings.length}) — run more hunts first`);
  }

  const members = findings.map((f) => ({
    fingerprint: f.fingerprint,
    source: f.source,
    title: f.title,
    cwe: f.cwe,
    severity: f.severity,
    status: f.status,
    verdict: f.verdict,
    evidence: f.evidence ?? [],
    rationale: f.rationale,
    // surface attack-relevant context the chainer reasons over
    verification: f.verification ? { attackVector: f.verification.attackVector, preconditions: f.verification.preconditions } : null
  }));

  // Attack-path scaffolding: destinations (assets), origins (entry points), and a
  // reachability summary so the chainer can SEARCH paths, not just compose findings.
  const assets = assetsFrom(store);
  const entryPoints = entryPointsFrom(store);
  const reachability = reachabilityFrom(store);

  const run = openRun(resolvedTarget, "chain");
  run.writeJson("prep.json", {
    runId: run.runId, runDir: run.runDir, target: resolvedTarget,
    findingsMtime: findingsDoc.generatedAt ?? null,
    memberCount: members.length, findings: members,
    context: { assets, entryPoints, reachability, hasThreatModel: assets.some((a) => a.from === "threat-model") },
    input
  });

  return {
    ok: true, status: "prepared", target: resolvedTarget, runId: run.runId, runDir: run.runDir,
    prepPath: join(run.runDir, "prep.json"), draftPath: join(run.runDir, "draft.chain.json"),
    memberCount: members.length,
    assetCount: assets.length, entryPointCount: entryPoints.length,
    assembleCommand: `node "${join(import.meta.dirname ?? resolve("."), "chain-finalize.mjs")}" --target "${resolvedTarget}" --run-dir "${run.runDir}"`
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("chain-prepare --target <path> [--input '{}']");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "input", "input-file"] });
  if (!flags.target) { console.error("chain-prepare: --target is required"); process.exit(1); }
  emitResult(prepareChain(flags.target, loadInput(flags)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
