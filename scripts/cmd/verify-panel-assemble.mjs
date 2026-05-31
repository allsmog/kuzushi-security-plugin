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
const NOISE_TOLERANCES = new Set(["precision", "recall", "ask"]);

function modal(values) {
  if (!values.length) return null;
  const counts = new Map();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best = null;
  let bestN = 0;
  for (const [k, v] of counts) if (v > bestN) { best = k; bestN = v; }
  return best;
}

// `opts.noiseTolerance` decides a SPLIT (no-majority) vote: "precision" drops it as
// not-exploitable, "recall" (default) keeps it as inconclusive for manual review,
// "ask" keeps it inconclusive and flags needsUserDecision so the skill can prompt.
export function consensus(votes, opts = {}) {
  const noiseTolerance = NOISE_TOLERANCES.has(opts.noiseTolerance) ? opts.noiseTolerance : "recall";
  const n = votes.length;
  const counts = { "confirmed-exploitable": 0, "not-exploitable": 0, inconclusive: 0 };
  for (const v of votes) counts[v.verdict] = (counts[v.verdict] ?? 0) + 1;

  // Winning side BEFORE the trigger downgrade — used for the confidence figure.
  const majoritySide =
    counts["confirmed-exploitable"] * 2 > n ? "confirmed-exploitable"
      : counts["not-exploitable"] * 2 > n ? "not-exploitable"
        : counts.inconclusive * 2 > n ? "inconclusive"
          : null;

  let verdict;
  let splitVote = false;
  let needsUserDecision = false;
  if (majoritySide) {
    verdict = majoritySide;
  } else {
    // No majority — break the tie by the operator's noise tolerance.
    splitVote = true;
    if (noiseTolerance === "precision") verdict = "not-exploitable";
    else { verdict = "inconclusive"; needsUserDecision = noiseTolerance === "ask"; }
  }

  // A "confirmed" consensus still requires a concrete trigger from some lens —
  // agreement alone isn't proof.
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

  // Confidence = mean across the votes that AGREE with the winning side (not all
  // votes): a 2/3 confirm shouldn't be diluted by the lone dissenter's confidence.
  const agreeingSide = majoritySide ?? verdict;
  const agreeing = votes.filter((v) => v.verdict === agreeingSide).map((v) => Number(v.confidence)).filter(Number.isFinite);
  const pool = agreeing.length ? agreeing : votes.map((v) => Number(v.confidence)).filter(Number.isFinite);
  const avgConfidence = pool.length ? pool.reduce((a, b) => a + b, 0) / pool.length : 0;

  // Audit trail for WHY the panel leaned non-finding: the modal exclusion rule and
  // the set of refute reasons among the not-exploitable votes.
  const fpVotes = votes.filter((v) => v.verdict === "not-exploitable");
  const exclusionRule = modal(fpVotes.map((v) => v.exclusionRule).filter((x) => x != null && x !== "none" && x !== ""));
  const refuteReasons = [...new Set(fpVotes.map((v) => v.refuteReason).filter((x) => x && x !== "n/a"))].sort();

  return {
    verdict,
    agreement: n ? Math.max(counts["confirmed-exploitable"], counts["not-exploitable"], counts.inconclusive) / n : 0,
    counts,
    voteCount: n,
    downgradedForNoTrigger: downgraded,
    splitVote,
    needsUserDecision,
    noiseTolerance,
    avgConfidence: Math.round(avgConfidence * 100) / 100,
    exclusionRule: exclusionRule ?? null,
    refuteReasons,
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
  // The split-vote tie-break policy travels in the prep's input (set via
  // /verify --input '{"noiseTolerance":"precision|recall|ask"}'); default recall.
  const prep = readJsonIfPresent(join(resolvedRunDir, "prep.json"));
  const noiseTolerance = prep?.input?.noiseTolerance ?? "recall";

  const results = [];
  const patches = [];
  for (const [fingerprint, votes] of byFinding) {
    const c = consensus(votes, { noiseTolerance });
    const tv = c.triggerVote;
    results.push({ findingFingerprint: fingerprint, verdict: c.verdict, agreement: c.agreement, counts: c.counts, voteCount: c.voteCount, downgradedForNoTrigger: c.downgradedForNoTrigger, splitVote: c.splitVote, needsUserDecision: c.needsUserDecision });
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
          splitVote: c.splitVote,
          needsUserDecision: c.needsUserDecision,
          noiseTolerance: c.noiseTolerance,
          ...(c.exclusionRule != null ? { exclusionRule: c.exclusionRule } : {}),
          ...(c.refuteReasons.length ? { refuteReasons: c.refuteReasons } : {}),
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
  // Under noiseTolerance "ask", these split-vote findings want a human call — the
  // skill surfaces them via AskUserQuestion instead of silently keeping/dropping.
  const needsUserDecision = results.filter((r) => r.needsUserDecision).map((r) => r.findingFingerprint);
  const run = openRun(resolvedTarget, "verify-panel-assemble");
  const result = {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    findingsVerified: results.length,
    verdictCounts,
    pocReadyCount: pocReady.length,
    pocReady,
    noiseTolerance,
    needsUserDecision,
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
