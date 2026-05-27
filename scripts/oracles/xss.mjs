import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "xss",
  cwes: ["CWE-79", "CWE-80", "CWE-83", "CWE-116"],
  description: "Output is escaped for the concrete HTML/JS/CSS/URL context while intended safe markup behavior is preserved.",
  positiveControl: "Benign display content renders as expected.",
  negativeControl: "Scriptable payloads render inert in the target output context.",
  exploitRegression: "The original payload cannot create executable markup or script.",
  behaviorPreservation: "Allowed formatting or safe HTML policy remains intact.",
  pocPlus: "Check context variants: element text, attribute, URL, JS string, CSS, markdown, and template boundaries."
});
