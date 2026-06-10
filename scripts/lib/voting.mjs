// Conservative majority vote over INDEPENDENT verifier verdicts.
//
// A single verification pass can let a non-exploitable finding through (or, rarer,
// reject a real one). Anthropic's defending-code harness found that running
// multiple independent verifiers and taking the majority "roughly halved the rate
// of non-exploitable findings." We run that vote HOST-side (the determinism
// boundary): the agent supplies N independent opinions; the host — not the model —
// decides the final verdict, so it can't be reasoned around.
//
// The goal is reducing FALSE POSITIVES, so the vote is conservative:
// "confirmed-exploitable" wins only with a STRICT majority; otherwise the most-
// supported safe verdict wins, and a true split collapses to "inconclusive"
// (needs more evidence) rather than over-claiming exploitability.

const VERIFY_VERDICTS = new Set(["confirmed-exploitable", "not-exploitable", "inconclusive"]);

export function majorityVerifyVerdict(votes) {
  const list = (votes ?? []).map(String).filter((v) => VERIFY_VERDICTS.has(v));
  const total = list.length;
  const tally = {};
  for (const v of list) tally[v] = (tally[v] ?? 0) + 1;
  if (total === 0) return { verdict: "inconclusive", agreement: 0, total: 0, tally };

  const exploit = tally["confirmed-exploitable"] ?? 0;
  const notExploit = tally["not-exploitable"] ?? 0;
  const half = total / 2;

  let verdict;
  if (exploit > half) verdict = "confirmed-exploitable";   // strict majority to CLAIM exploitable
  else if (notExploit > half) verdict = "not-exploitable"; // strict majority to clear it
  else verdict = "inconclusive";                            // split / no majority → conservative

  const agreement = Number(((tally[verdict] ?? 0) / total).toFixed(3));
  return { verdict, agreement, total, tally };
}
