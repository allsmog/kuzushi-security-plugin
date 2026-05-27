// Tool-boundary policy plane.
//
// A single effective policy governs the plugin's risk surfaces: which paths
// generated/queried files may live in, whether raw (non-pack) analyzer queries
// may execute, the inline-script size cap, hook error posture, install/download
// posture, and the posture for working-tree writes. The shipped default remains
// developer-friendly, but named profiles provide review-safe and ci-locked
// hardening without requiring users to rewrite the full policy.
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
import { assertValid } from "./schemas.mjs";

export const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_POLICY_PATH = join(PLUGIN_ROOT, "policy.default.json");

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

const PROFILE_KEYS = new Set(["profiles", "activeProfile"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function withoutProfileKeys(policy) {
  const out = {};
  for (const [key, value] of Object.entries(policy ?? {})) {
    if (!PROFILE_KEYS.has(key)) out[key] = value;
  }
  return out;
}

// Deep-merge an override onto the default so profile snippets can change one
// nested key without discarding siblings.
function mergePolicy(base, override) {
  if (!override) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = isPlainObject(value) && isPlainObject(base[key])
      ? mergePolicy(base[key], value)
      : value;
  }
  return out;
}

// Effective policy for a target:
//   default base ← selected profile ← optional .kuzushi/policy.json fields.
// If the override sets activeProfile, that profile is selected first, then the
// override's concrete fields win. This lets CI set `{ "activeProfile":
// "ci-locked" }` without copying the profile body.
export function loadPolicy(target = process.cwd()) {
  const def = readJson(DEFAULT_POLICY_PATH) ?? {};
  const overridePath = join(resolve(target), ".kuzushi", "policy.json");
  const override = existsSync(overridePath) ? readJson(overridePath) : null;
  const profiles = mergePolicy(def.profiles ?? {}, override?.profiles ?? {});
  const activeProfile = override?.activeProfile ?? def.activeProfile ?? "developer-fast";
  const profile = profiles[activeProfile] ?? {};
  const effective = mergePolicy(mergePolicy(withoutProfileKeys(def), profile), withoutProfileKeys(override));
  effective.activeProfile = activeProfile;
  effective.profiles = profiles;
  assertValid("policy", effective);
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

export function hookErrorDecision(target = process.cwd()) {
  const { effective } = loadPolicy(target);
  return effective.guardrails?.onHookError ?? "allow";
}

export function autoInstallAllowed(target = process.cwd()) {
  const { effective } = loadPolicy(target);
  const value = effective.install?.autoInstallLightTools;
  return value === true || value === "allow";
}

export function networkInstallAllowed(target = process.cwd(), { approved = false, tool = null } = {}) {
  const { effective } = loadPolicy(target);
  const install = effective.install ?? {};
  const decision = install.allowNetworkInstall ?? "approval-only";
  if (decision === "deny") {
    return { ok: false, blocked: "install", reason: "policy.install.allowNetworkInstall=deny: tool downloads are disabled" };
  }
  if (decision === "approval-only" && !approved) {
    return {
      ok: false,
      blocked: "install",
      requiresApproval: true,
      reason: `policy.install.allowNetworkInstall=approval-only: ${tool ?? "tool"} install requires explicit approval`
    };
  }
  return { ok: true, requirePinnedDigests: Boolean(install.requirePinnedDigests) };
}
