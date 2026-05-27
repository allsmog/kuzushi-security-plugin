import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "memory-safety",
  cwes: ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127", "CWE-131", "CWE-190", "CWE-191", "CWE-415", "CWE-416", "CWE-476", "CWE-787", "CWE-824"],
  description: "Sanitizer or crash input no longer triggers memory corruption while valid inputs still parse/execute.",
  positiveControl: "A valid seed input runs cleanly under sanitizers.",
  negativeControl: "The minimized crashing input and nearby malformed variants run without sanitizer findings after the fix.",
  exploitRegression: "The original sanitizer crash no longer fires.",
  behaviorPreservation: "Expected parser/library behavior for valid corpus entries is unchanged.",
  pocPlus: "Check minimized crash, neighboring length/offset variants, empty input, maximum-size input, and corpus valid cases."
});
