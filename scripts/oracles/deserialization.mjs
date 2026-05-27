import { makeOracle } from "./common.mjs";

export const oracle = makeOracle({
  id: "deserialization",
  cwes: ["CWE-502"],
  description: "Dangerous gadget/object types are rejected while benign serialized objects still round-trip.",
  positiveControl: "A benign serialized object of an allowed type deserializes successfully.",
  negativeControl: "Unexpected types, gadget markers, external references, and polymorphic bypasses are rejected.",
  exploitRegression: "The original gadget path no longer reaches object construction or side effects.",
  behaviorPreservation: "Allowed serialization formats remain backwards-compatible where required.",
  pocPlus: "Check type confusion, nested objects, aliases, version markers, and compression/wrapper variants."
});
