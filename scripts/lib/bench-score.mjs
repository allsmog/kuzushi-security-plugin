// Recall / precision / false-proof scorer for the kuzushi benchmark.
//
// You cannot claim "world-class bug finding" — or catch a regression in it —
// without a number. This is the measurement instrument: given a ground-truth
// manifest (what a target actually contains, both real bugs AND decoys that must
// NOT be flagged) and the findings.json a run produced, it computes the three
// metrics that matter:
//   - recall    = real bugs found / real bugs present   (are we MISSING bugs?)
//   - precision = true hits / all hits                  (do we cry wolf?)
//   - falseProofRate = proven hits on decoys / proven   (did we PROVE a non-bug?)
//
// Pure and deterministic so it runs in CI and gates changes to the producers.

// CWE comparison is forgiving of formatting: "CWE-78", "cwe_078", 78 all match.
function normalizeCwe(cwe) {
  if (cwe == null) return null;
  const m = String(cwe).match(/\d+/);
  return m ? String(parseInt(m[0], 10)) : null;
}

// Files may be absolute on one side and repo-relative on the other; compare the
// path tail so a match isn't lost to layout. Returns true if either is a suffix
// of the other (path-segment aligned).
function samePath(a, b) {
  if (!a || !b) return false;
  const na = String(a).replace(/\\/g, "/");
  const nb = String(b).replace(/\\/g, "/");
  if (na === nb) return true;
  const long = na.length >= nb.length ? na : nb;
  const short = na.length >= nb.length ? nb : na;
  return long === short || long.endsWith(`/${short}`);
}

// Active = the finding was promoted/kept, not triaged away. Only active findings
// count as alarms; a `rejected`/`reviewed`/`noise` finding is the tool correctly
// declining, so it must not count against precision.
const INACTIVE_STATUS = new Set(["reviewed", "noise", "rejected"]);
function isActive(finding) {
  return !INACTIVE_STATUS.has(String(finding.status ?? ""));
}

function anchorOf(finding) {
  const a = (finding.evidence ?? [])[0] ?? {};
  return { filePath: a.filePath, line: Number(a.startLine ?? a.line ?? 0) };
}

// Does `finding` land on `expected`? Same file, line within tolerance, and —
// when both carry a CWE and matchCwe is on — the same CWE.
function findingMatches(finding, expected, { lineTolerance, matchCwe }) {
  const anchor = anchorOf(finding);
  if (!samePath(anchor.filePath, expected.filePath)) return false;
  if (Number.isFinite(expected.line) && expected.line > 0) {
    if (Math.abs(anchor.line - expected.line) > lineTolerance) return false;
  }
  if (matchCwe) {
    const fc = normalizeCwe(finding.cwe);
    const ec = normalizeCwe(expected.cwe);
    if (fc && ec && fc !== ec) return false;
  }
  return true;
}

// Score actual findings against a ground-truth manifest.
//   groundTruth.expectations[]: { id, kind: "vuln"|"safe", cwe?, filePath, line? }
//   actual: array of finding.v1 objects (or a findings.json document)
// opts: { lineTolerance=5, matchCwe=true, strict=false }
//   strict: an active finding matching NO expectation counts as a false positive
//   (only fair when the manifest is exhaustively annotated).
export function scoreFindings(groundTruth, actual, opts = {}) {
  const lineTolerance = Number(opts.lineTolerance ?? 5);
  const matchCwe = opts.matchCwe !== false;
  const strict = Boolean(opts.strict);

  const expectations = groundTruth.expectations ?? groundTruth.findings ?? [];
  const findings = Array.isArray(actual) ? actual : (actual?.findings ?? []);
  const active = findings.filter(isActive);

  const matchedFindings = new Set();
  const perExpectation = [];
  let truePositives = 0;
  let falseNegatives = 0;
  let falsePositivesOnDecoys = 0;
  let falseProofs = 0;

  for (const exp of expectations) {
    const hits = active.filter((f) => findingMatches(f, exp, { lineTolerance, matchCwe }));
    hits.forEach((f) => matchedFindings.add(f));
    if (exp.kind === "safe") {
      // A decoy: any active hit here is a false alarm. A *proven* hit is worse —
      // it's a false proof (the soundness failure differential testing guards).
      const provenHit = hits.some((f) => f.status === "proven" || f.poc?.proofVerdict === "exploited");
      if (hits.length) falsePositivesOnDecoys += 1;
      if (provenHit) falseProofs += 1;
      perExpectation.push({ id: exp.id, kind: "safe", outcome: hits.length ? "false-positive" : "correctly-ignored", hitCount: hits.length, provenHit });
    } else {
      if (hits.length) { truePositives += 1; perExpectation.push({ id: exp.id, kind: "vuln", outcome: "found", hitCount: hits.length }); }
      else { falseNegatives += 1; perExpectation.push({ id: exp.id, kind: "vuln", outcome: "missed", hitCount: 0 }); }
    }
  }

  // Findings that matched no expectation at all. In strict mode these are FPs.
  const unmatched = active.filter((f) => !matchedFindings.has(f));
  const falsePositives = falsePositivesOnDecoys + (strict ? unmatched.length : 0);

  const provenCount = findings.filter((f) => f.status === "proven" || f.poc?.proofVerdict === "exploited").length;
  const ratio = (num, den) => (den === 0 ? null : Number((num / den).toFixed(4)));

  return {
    truePositives,
    falseNegatives,
    falsePositives,
    falseProofs,
    vulnTotal: truePositives + falseNegatives,
    decoyTotal: expectations.filter((e) => e.kind === "safe").length,
    provenCount,
    unmatchedCount: unmatched.length,
    recall: ratio(truePositives, truePositives + falseNegatives),
    precision: ratio(truePositives, truePositives + falsePositives),
    falseProofRate: ratio(falseProofs, provenCount),
    perExpectation,
    unmatched: unmatched.map((f) => ({ fingerprint: f.fingerprint, cwe: f.cwe, ...anchorOf(f), status: f.status }))
  };
}

export const _internals = { normalizeCwe, samePath, findingMatches, isActive };
