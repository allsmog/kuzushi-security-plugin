#!/usr/bin/env node
// Panel finalize for /verify. A single verifier can be confidently wrong; the panel
// runs N independent verifiers (different lenses — reachability, guard-bypass,
// impact) and only a MAJORITY confirms. This is kuzushi's precision engine: it keeps
// the extra recall from /deep-scan from arriving as false-positive noise. Each lens
// wrote draft.verify.<k>.json (the normal verify draft shape); this aggregates them
// by finding fingerprint, computes consensus, and patches findings.json once.

import { resolve, join } from "node:path";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { patchFindings, verifyVerdictToStatus } from "../lib/findings.mjs";

const VALID_VERDICTS = new Set(["confirmed-exploitable", "not-exploitable", "inconclusive"]);
const POC_READY = new Set(["confirmed-exploitable", "inconclusive"]);
const MIN_RATIONALE = 80; // per-vote; lighter than single-pass since N votes corroborate

function fail(message) {
  console.error(`verify-panel-assemble: ${message}`);
  process.exit(1);
}

// Majority consensus across votes for one finding. A "confirmed-exploitable"
// consensus additionally REQUIRES at least one vote that supplied a concrete
// trigger (pocSketch{payload,howToTrigger} + an evidence anchor) — otherwise there
// is no demonstrated exploit and we downgrade to inconclusive. This is the panel's
// FP gate: agreement alone isn't proof; a trigger is.
export function consensus(votes) {
  const n = votes.length;
  const counts = { "confirmed-exploitable": 0, "not-exploitable": 0, inconclusive: 0 };
  for (const v of votes) counts[v.verdict] = (counts[v.verdict] ?? 0) + 1;

  let verdict = "inconclusive";
  if (counts["confirmed-exploitable"] * 2 > n) verdict = "confirmed-exploitable";
  else if (counts["not-exploitable"] * 2 > n) verdict = "not-exploitable";

  const triggerVote = votes.find((v) =>
    v.verdict === "confirmed-exploitable" &&
    v.pocSketch && v.pocSketch.payload && v.pocSketch.howToTrigger &&
    Array.isArray(v.evidenceAnchors) && v.evidenceAnchors.length
  );
  let downgraded = false;
  if (verdict === "confirmed-exploitable" && !triggerVote) {
    verdict = "inconclusive";
    downgraded = true;
  }

  const confidences = votes.map((v) => Number(v.confidence)).filter(Number.isFinite);
  const avgConfidence = confidences.length ? confidences.reduce((a, b) => a + b, 0) / confidences.length : 0;

  return {
    verdict,
    agreement: n ? Math.max(counts["confirmed-exploitable"], counts["not-exploitable"], counts.inconclusive) / n : 0,
    counts,
    voteCount: n,
    downgradedForNoTrigger: downgraded,
    avgConfidence: Math.round(avgConfidence * 100) / 100,
    triggerVote: triggerVote ?? null
  };
}

function loadVotesByFinding(runDir) {
  const drafts = readdirSync(runDir)
    .filter((f) => /^draft\.verify\.\d+\.json$/.test(f))
    .sort();
  if (!drafts.length) fail(`no draft.verify.<k>.json files in ${runDir} (panel mode expects one per lens)`);
  const byFinding = new Map();
  for (const file of drafts) {
    let draft;
    try { draft = JSON.parse(readFileSync(join(runDir, file), "utf8")); } catch { fail(`${file} is not valid JSON`); }
    if (!Array.isArray(draft.candidates)) fail(`${file}: must have a candidates[] array`);
    const lens = draft.lens ?? file;
    for (const c of draft.candidates) {
      if (!c.findingFingerprint) fail(`${file}: a candidate is missing findingFingerprint`);
      if (!VALID_VERDICTS.has(c.verdict)) fail(`${file}: invalid verdict "${c.verdict}" for ${c.findingFingerprint}`);
      if (String(c.rationale ?? "").length < MIN_RATIONALE) fail(`${file}: ${c.findingFingerprint} rationale < ${MIN_RATIONALE} chars`);
      if (!byFinding.has(c.findingFingerprint)) byFinding.set(c.findingFingerprint, []);
      byFinding.get(c.findingFingerprint).push({ lens, ...c });
    }
  }
  return byFinding;
}

export function assembleVerifyPanel(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);
  if (!existsSync(resolvedRunDir)) fail(`run dir not found: ${resolvedRunDir}`);

  const byFinding = loadVotesByFinding(resolvedRunDir);
  const verifiedAt = new Date().toISOString();

  const results = [];
  const patches = [];
  for (const [fingerprint, votes] of byFinding) {
    const c = consensus(votes);
    const tv = c.triggerVote;
    results.push({ findingFingerprint: fingerprint, verdict: c.verdict, agreement: c.agreement, counts: c.counts, voteCount: c.voteCount, downgradedForNoTrigger: c.downgradedForNoTrigger });
    patches.push({
      fingerprint,
      status: verifyVerdictToStatus(c.verdict),
      verification: {
        schemaVersion: "verification.v1",
        verdict: c.verdict,
        confidence: c.avgConfidence,
        pocSketch: tv?.pocSketch ?? null,
        pocReady: POC_READY.has(c.verdict),
        panel: {
          voteCount: c.voteCount,
          agreement: c.agreement,
          counts: c.counts,
          downgradedForNoTrigger: c.downgradedForNoTrigger,
          votes: votes.map((v) => ({ lens: v.lens, verdict: v.verdict, confidence: Number(v.confidence) || 0 }))
        },
        verifiedAt
      }
    });
  }

  const doc = { version: "1.0", schemaVersion: "verify-panel.v1", generatedAt: verifiedAt, target: resolvedTarget, results };
  atomicWrite(store.verifyPath, `${JSON.stringify(doc, null, 2)}\n`);
  atomicWrite(join(resolvedRunDir, "verify-panel.json"), `${JSON.stringify(doc, null, 2)}\n`);

  const findingsDoc = patchFindings(resolvedTarget, patches);

  const verdictCounts = results.reduce((acc, r) => { acc[r.verdict] = (acc[r.verdict] ?? 0) + 1; return acc; }, {});
  const pocReady = results.filter((r) => POC_READY.has(r.verdict)).map((r) => r.findingFingerprint);
  const run = openRun(resolvedTarget, "verify-panel-assemble");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    findingsVerified: results.length,
    verdictCounts,
    pocReadyCount: pocReady.length,
    pocReady,
    verifyPath: store.verifyPath,
    findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("verify-panel-assemble --target <path> --run-dir <dir>  (reads draft.verify.<k>.json per lens)");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(assembleVerifyPanel(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
