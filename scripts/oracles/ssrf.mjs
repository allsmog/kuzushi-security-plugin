import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "ssrf",
  cwes: ["CWE-918"],
  description: "Forbidden network destinations are blocked without breaking explicitly allowed destinations.",
  positiveControl: "An allowed, local stub destination succeeds without real internet access.",
  negativeControl: "Loopback, link-local, metadata, private-range, and DNS-rebinding-style destinations are rejected.",
  exploitRegression: "The original forbidden sink request is blocked before network dispatch.",
  behaviorPreservation: "Allowed service calls continue to use the intended client path.",
  pocPlus: "Check URL parser variants: redirects, credentials, IPv6, integer IPs, DNS aliases, and scheme confusion."
});
