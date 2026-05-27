import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "path-traversal",
  cwes: ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
  description: "Outside-root access must fail while inside-root access and benign path normalization still work.",
  positiveControl: "A path inside the configured root is accepted and returns the expected file/resource.",
  negativeControl: "Traversal, absolute-path, encoded traversal, and symlink escape inputs are rejected.",
  exploitRegression: "The original traversal payload no longer reaches an outside-root file.",
  behaviorPreservation: "Legitimate relative paths under the root still resolve.",
  pocPlus: "Check traversal variants: ../, encoded separators, mixed separators, absolute paths, and symlink escapes."
});
