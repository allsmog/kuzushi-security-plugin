import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "authz",
  cwes: ["CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
  description: "The same operation is allowed for an authorized actor and denied for an unauthorized actor.",
  positiveControl: "User A can perform an action on User A's own resource when policy permits.",
  negativeControl: "User B cannot perform the same action on User A's resource.",
  exploitRegression: "The original bypass path is denied with the expected authz failure.",
  behaviorPreservation: "Legitimate role/owner flows still succeed.",
  pocPlus: "Check direct object references, alternate routes, method overrides, cached decisions, and role boundary variants."
});
