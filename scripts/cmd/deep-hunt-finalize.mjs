#!/usr/bin/env node
// Finalize phase for /deep-hunt. Validates the deep-hunter's interprocedural flows
// (closed verdict set; a "finding" must carry a confirmed cross-file path), persists
// .kuzushi/deep-hunt.json, and promotes verdicts into findings.json (source
// "deep-hunt"). The cross-file path is stored as the finding's `evidenceGraph` so the
// full source→…→sink trail survives into /verify, /report, and /chain. Like
// /deep-scan, a deep-hunt "finding" is an un-pattern-gated lead — it should flow
// through /verify (panel) before being treated as confirmed.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const VALID_EVIDENCE = new Set(["path", "linked", "candidate"]);
const MIN_RATIONALE_LENGTH = 150;
const MIN_SELFCHECK_LENGTH = 40;

function fail(message) {
  console.error(`deep-hunt-finalize: ${message}`);
  process.exit(1);
}

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// A finding's interprocedural path: ≥2 hops spanning ≥2 distinct files. This is the
// gate that keeps deep-hunt honest — a "finding" must be an actual cross-file flow,
// not a single-site hunch (that's what /deep-scan and the other producers already do).
function pathFiles(path) {
  return new Set((Array.isArray(path) ? path : []).map((p) => norm(p.filePath)).filter(Boolean));
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.huntId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.evidenceLevel && !VALID_EVIDENCE.has(c.evidenceLevel)) {
      fail(`item ${id}: invalid evidenceLevel "${c.evidenceLevel}"; must be one of ${[...VALID_EVIDENCE].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Show the cross-file data path + the trusted assumption that breaks.`);
    }
    if (c.verdict === "finding") {
      if (!c.cwe) fail(`item ${id}: verdict "finding" requires a cwe (e.g. "CWE-89").`);
      const path = Array.isArray(c.path) ? c.path : [];
      if (path.length < 2) fail(`item ${id}: verdict "finding" requires a path[] with ≥2 hops (the interprocedural flow). Got ${path.length}.`);
      for (const hop of path) {
        if (!hop.filePath || hop.startLine === undefined) fail(`item ${id}: each path hop must be { filePath, startLine, role }.`);
      }
      if (pathFiles(path).size < 2) {
        fail(`item ${id}: verdict "finding" requires the path to span ≥2 distinct files (an interprocedural flow). Use "candidate" for a single-file flow — that's /deep-scan's job.`);
      }
      if (String(c.selfCheck ?? "").length < MIN_SELFCHECK_LENGTH) {
        fail(`item ${id}: verdict "finding" requires a selfCheck (≥${MIN_SELFCHECK_LENGTH} chars): the guard/invariant that would make this safe, confirmed absent or insufficient.`);
      }
    }
  }
}

// Map the ordered path hops to the finding schema's evidenceGraph {nodes, edges}.
function evidenceGraphOf(path) {
  const hops = (Array.isArray(path) ? path : []).filter((h) => h?.filePath);
  const nodes = hops.map((h, i) => ({ id: i, filePath: norm(h.filePath), startLine: Number(h.startLine) || 1, role: h.role ?? "" }));
  const edges = nodes.slice(1).map((_, i) => ({ from: i, to: i + 1 }));
  return { nodes, edges };
}

// Evidence anchors = the two ends of the flow (source + sink), falling back to the
// path endpoints, so fingerprinting and the report's file:line both work.
function evidenceOf(c) {
  const anchors = [];
  const src = c.source ?? (Array.isArray(c.path) ? c.path[0] : null);
  const sink = c.sink ?? (Array.isArray(c.path) ? c.path[c.path.length - 1] : null);
  if (src?.filePath) anchors.push({ filePath: norm(src.filePath), startLine: Number(src.startLine) || 1 });
  if (sink?.filePath) anchors.push({ filePath: norm(sink.filePath), startLine: Number(sink.startLine) || 1 });
  return anchors.length ? anchors : [{ filePath: ".", startLine: 1 }];
}

export function finalizeDeepHunt(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.deep-hunt.json");
  if (!existsSync(draftPath)) fail(`no draft.deep-hunt.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.deep-hunt.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(store.deepHuntPath, json);
  atomicWrite(join(resolvedRunDir, "deep-hunt.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const graph = evidenceGraphOf(c.path);
    return {
      source: "deep-hunt",
      refId: c.huntId ?? `dh-${i + 1}`,
      title: c.title ?? `Interprocedural flow ${i + 1}`,
      severity: c.severity ?? "",
      cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      evidence: evidenceOf(c),
      ...(graph.nodes.length ? { evidenceGraph: graph } : {}),
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : ["/verify (panel) this interprocedural lead before treating it as confirmed"],
      ...(c.evidenceLevel ? { evidenceLevel: c.evidenceLevel } : {}),
      ...(c.selfCheck ? { selfCheck: String(c.selfCheck) } : {})
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "deep-hunt-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    deepHuntPath: store.deepHuntPath, findingsPath: store.findingsPath, findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("deep-hunt-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeDeepHunt(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
