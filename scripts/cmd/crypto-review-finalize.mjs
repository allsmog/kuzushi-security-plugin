#!/usr/bin/env node
// Finalize phase for /crypto-review. Validates the crypto-misuse verdicts the
// agent drafted, persists .kuzushi/crypto-review.json, and promotes verdicts into
// .kuzushi/findings.json (source "crypto-review"). Self-contained: the canonical
// artifact path is derived from store.root (no shared artifact-store edit needed).

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, openRun, atomicWrite, emitResult } from "../lib/artifact-store.mjs";
import { upsertFindings, verdictToStatus } from "../lib/findings.mjs";
import { severityFieldsFor } from "../lib/severity.mjs";

const VALID_VERDICTS = new Set(["finding", "candidate", "rejected"]);
const MIN_RATIONALE_LENGTH = 150;
const VALID_CATEGORIES = new Set(["timing-side-channel", "missing-zeroization", "weak-crypto-rng"]);

function fail(message) {
  console.error(`crypto-review-finalize: ${message}`);
  process.exit(1);
}

function validate(candidates) {
  for (const c of candidates) {
    const id = c.cryptoId ?? c.id ?? "(unknown)";
    if (!VALID_VERDICTS.has(c.verdict)) {
      fail(`item ${id}: invalid verdict "${c.verdict}"; must be one of ${[...VALID_VERDICTS].join(", ")}`);
    }
    if (c.category && !VALID_CATEGORIES.has(c.category)) {
      fail(`item ${id}: invalid category "${c.category}"; must be one of ${[...VALID_CATEGORIES].join(", ")}`);
    }
    const rationale = String(c.rationale ?? "");
    if (rationale.length < MIN_RATIONALE_LENGTH) {
      fail(`item ${id}: rationale is ${rationale.length} chars (min ${MIN_RATIONALE_LENGTH}). Confirm the value is secret-derived and state the leak / weakness + the constant-time / zeroization fix.`);
    }
    if (c.verdict === "finding") {
      const anchors = Array.isArray(c.evidenceAnchors) ? c.evidenceAnchors : [];
      if (!anchors.length) fail(`item ${id}: verdict "finding" requires at least one evidenceAnchor { filePath, startLine }.`);
      for (const a of anchors) {
        if (!a.filePath || a.startLine === undefined) fail(`item ${id}: each evidenceAnchor must be { filePath, startLine }.`);
      }
    }
  }
}

export function finalizeCryptoReview(target, runDir) {
  const resolvedTarget = resolve(target);
  const resolvedRunDir = resolve(runDir);
  const store = storeFor(resolvedTarget);

  const draftPath = join(resolvedRunDir, "draft.crypto-review.json");
  if (!existsSync(draftPath)) fail(`no draft.crypto-review.json in ${resolvedRunDir}`);
  let draft;
  try { draft = JSON.parse(readFileSync(draftPath, "utf8")); } catch { fail("draft.crypto-review.json is not valid JSON"); }
  if (!Array.isArray(draft.candidates)) fail("draft must have a candidates[] array");

  validate(draft.candidates);

  const cryptoReviewPath = join(store.root, "crypto-review.json");
  const json = `${JSON.stringify(draft, null, 2)}\n`;
  atomicWrite(cryptoReviewPath, json);
  atomicWrite(join(resolvedRunDir, "crypto-review.json"), json);

  const newFindings = draft.candidates.map((c, i) => {
    const anchors = (c.evidenceAnchors ?? []).map((a) => ({ filePath: a.filePath, startLine: a.startLine }));
    return {
      source: "crypto-review",
      refId: c.cryptoId ?? `${c.category ?? "crypto"}-${i + 1}`,
      title: c.title ?? `Crypto misuse: ${c.category ?? "issue"}`,
      ...severityFieldsFor(c),
      cwe: (Array.isArray(c.cwe) ? c.cwe[0] : c.cwe) ?? "",
      verdict: c.verdict,
      status: verdictToStatus(c.verdict),
      evidence: anchors,
      rationale: String(c.rationale ?? ""),
      nextChecks: Array.isArray(c.nextChecks) ? c.nextChecks : [],
      ...(c.category ? { category: c.category } : {})
    };
  });
  const findingsDoc = upsertFindings(resolvedTarget, newFindings);

  const verdictCounts = draft.candidates.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] ?? 0) + 1; return acc; }, {});
  const run = openRun(resolvedTarget, "crypto-review-finalize");
  const result = {
    ok: true, status: "completed", target: resolvedTarget,
    itemCount: draft.candidates.length, verdictCounts,
    cryptoReviewPath, findingsPath: store.findingsPath,
    findingsSummary: findingsDoc.summary
  };
  run.finalize(result);
  return result;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("crypto-review-finalize --target <path> --run-dir <dir>");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "run-dir"] });
  if (!flags.target || !flags["run-dir"]) fail("--target and --run-dir are required");
  emitResult(finalizeCryptoReview(flags.target, flags["run-dir"]));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
