import { oracle as pathTraversal } from "../oracles/path-traversal.mjs";
import { oracle as ssrf } from "../oracles/ssrf.mjs";
import { oracle as sqlInjection } from "../oracles/sql-injection.mjs";
import { oracle as xss } from "../oracles/xss.mjs";
import { oracle as authz } from "../oracles/authz.mjs";
import { oracle as deserialization } from "../oracles/deserialization.mjs";
import { oracle as memorySafety } from "../oracles/memory-safety.mjs";

export const ORACLES = [
  pathTraversal,
  ssrf,
  sqlInjection,
  xss,
  authz,
  deserialization,
  memorySafety
];

function normalizeCwe(cwe) {
  const value = Array.isArray(cwe) ? cwe[0] : cwe;
  const m = /^CWE-(\d+)$/i.exec(String(value ?? "").trim());
  return m ? `CWE-${m[1]}` : String(value ?? "").trim().toUpperCase();
}

export function oracleForCwe(cwe) {
  const normalized = normalizeCwe(cwe);
  return ORACLES.find((oracle) => oracle.cwes.includes(normalized)) ?? null;
}

export function oracleSummaryForFinding(finding) {
  const oracle = oracleForCwe(finding?.cwe);
  if (!oracle) return null;
  return {
    id: oracle.id,
    cwes: oracle.cwes,
    description: oracle.description,
    controls: oracle.controls
  };
}
