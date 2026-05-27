import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "sql-injection",
  cwes: ["CWE-89"],
  description: "Untrusted input must not change query structure; queries remain parameterized.",
  positiveControl: "A benign input returns the expected result through the same query path.",
  negativeControl: "Injection payloads do not alter predicates, add statements, or change row count semantics.",
  exploitRegression: "The original payload is passed as data, not SQL syntax.",
  behaviorPreservation: "The intended query still works for normal inputs.",
  pocPlus: "Check quote, comment, boolean, stacked-query, wildcard, and encoding variants against a local test database."
});
