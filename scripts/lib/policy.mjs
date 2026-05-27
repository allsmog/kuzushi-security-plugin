// Tool-boundary policy plane.
//
// A single effective policy governs the plugin's risk surfaces: which paths
// generated/queried files may live in, whether raw (non-pack) analyzer queries
// may execute, the inline-script size cap, and the posture for working-tree
// writes. The shipped default (policy.default.json at the plugin root) is
// non-breaking — `mcp.rawQuery: "allow"` preserves today's behavior — but a
// per-target `<target>/.kuzushi/policy.json` override can tighten it to
// "require-approval" or "deny" for locked-down environments.
//
// Always-on (independent of rawQuery): query PATH CONFINEMENT (a .ql file or
// CPG path must resolve under the target tree, the plugin root, or the OS temp
// dir — never /etc, ~/.ssh, or other escapes) and an inline-script SIZE CAP.
// These add real containment without breaking the plugin's own analysis.

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

export const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_POLICY_PATH = join(PLUGIN_ROOT, "policy.default.json");

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

// Shallow-merge an override onto the default, one level deep per top-level key
// (so `{ mcp: { rawQuery: "deny" } }` only changes rawQuery, keeping the rest).
function mergePolicy(base, override) {
  if (!override) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = value && typeof value === "object" && !Array.isArray(value) && typeof base[key] === "object"
      ? { ...base[key], ...value }
      : value;
  }
  return out;
}

// Effective policy for a target: plugin default ← optional .kuzushi/policy.json.
export function loadPolicy(target = process.cwd()) {
  const def = readJson(DEFAULT_POLICY_PATH) ?? {};
  const overridePath = join(resolve(target), ".kuzushi", "policy.json");
  const override = existsSync(overridePath) ? readJson(overridePath) : null;
  const effective = mergePolicy(def, override);
  return { effective, sources: { default: DEFAULT_POLICY_PATH, override: override ? overridePath : null } };
}

// Stable short digest of the effective policy (for provenance + attestation).
export function policyDigest(target = process.cwd()) {
  const { effective } = loadPolicy(target);
  return createHash("sha256").update(JSON.stringify(effective)).digest("hex").slice(0, 16);
}

// Is `child` within `root` (no `..` escape)? Both resolved.
function isWithin(root, child) {
  const rel = relative(resolve(root), resolve(child));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

// Walk up from a path to the nearest ancestor containing a .kuzushi dir — that
// is the target root. Falls back to cwd so MCP servers (which don't get an
// explicit --target) still resolve a sensible root.
export function inferTarget(fromPath) {
  let dir = resolve(fromPath ?? process.cwd());
  if (!existsSync(dir) || !isAbsolute(dir)) dir = process.cwd();
  for (let i = 0; i < 40; i++) {
    if (existsSync(join(dir, ".kuzushi"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

// The roots a queried/generated file is allowed to resolve under.
function allowedRoots(target) {
  return [resolve(target), PLUGIN_ROOT, resolve(tmpdir())];
}

// Gate an analyzer query before execution. Used by the codeql / joern MCP
// servers. Returns { ok:true } to proceed, or a structured refusal the server
// passes straight back to the caller.
//   queryPath   — path to a .ql file (codeql) or null for inline
//   inlineScript— inline script body (joern) or null
//   fromPath    — a path that locates the target (db/cpg path), for target inference
export function assertQueryAllowed({ queryPath = null, inlineScript = null, fromPath = null } = {}) {
  const target = inferTarget(fromPath ?? queryPath);
  const { effective } = loadPolicy(target);
  const mcp = effective.mcp ?? {};
  const maxBytes = Number(mcp.maxQueryBytes ?? 200000);

  // Always-on: inline-script size cap.
  if (inlineScript != null && Buffer.byteLength(inlineScript, "utf8") > maxBytes) {
    return { ok: false, blocked: "size", reason: `inline script exceeds maxQueryBytes (${maxBytes})` };
  }

  // Always-on: path confinement for file-backed queries.
  if (queryPath != null && (mcp.confineQueryPaths ?? true)) {
    const roots = allowedRoots(target);
    if (!roots.some((r) => isWithin(r, queryPath))) {
      return {
        ok: false,
        blocked: "path",
        reason: `query path escapes allowed roots (target / plugin / tmp): ${queryPath}`,
        allowedRoots: roots
      };
    }
  }

  // Configurable raw-query gate. A query is "from the pack" when it lives under
  // <target>/.kuzushi/rules/ (validated, digest-tracked). Pack queries always
  // run. Raw queries obey policy.mcp.rawQuery (allow | require-approval | deny).
  const rawDecision = String(mcp.rawQuery ?? "allow");
  const packDir = join(resolve(target), ".kuzushi", "rules");
  const fromPack = queryPath != null && isWithin(packDir, queryPath);
  if (!fromPack && rawDecision !== "allow") {
    if (rawDecision === "deny") {
      return { ok: false, blocked: "raw-query", reason: "policy.mcp.rawQuery=deny: raw analyzer queries are disabled; use the validated rule pack (/rule-synth)" };
    }
    // require-approval: honor a per-target approval marker.
    const marker = join(resolve(target), ".kuzushi", ".approvals", "raw-query");
    if (!existsSync(marker)) {
      return {
        ok: false,
        blocked: "raw-query",
        requiresApproval: true,
        reason: "policy.mcp.rawQuery=require-approval: raw analyzer query needs approval",
        hint: `create ${relative(target, marker)} to approve, set policy.mcp.rawQuery=allow, or run a validated pack query (/rule-synth)`
      };
    }
  }

  return { ok: true, target, fromPack };
}

// Is a subprocess command on the exec allowlist? (advisory helper for callers
// that want to check before spawning; the bash guardrail is the hard gate.)
export function execAllowed(target, command) {
  const { effective } = loadPolicy(target);
  const list = effective.exec?.subprocessAllowlist ?? [];
  return list.includes(command);
}
