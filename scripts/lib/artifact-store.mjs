// Artifact store: paths, run-id mint, atomic writes.
//
// The store directory is <target>/.kuzushi/. If a target still has a
// <target>/.security-agent/ directory left over from a brief naming
// detour, we migrate it to .kuzushi/ on first access (atomic same-fs
// rename in the common case; recursive copy + delete as a fallback).
// Callers must go through storeFor(target) — do not hardcode paths.

import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { provenanceFor } from "./provenance.mjs";

const STORE_DIR_NAME = ".kuzushi";
const LEGACY_STORE_DIR_NAME = ".security-agent";

function migrateLegacyStore(target) {
  const legacy = resolve(target, LEGACY_STORE_DIR_NAME);
  const current = resolve(target, STORE_DIR_NAME);
  if (!existsSync(legacy) || existsSync(current)) return;
  try {
    renameSync(legacy, current);
  } catch (error) {
    if (error.code === "EXDEV") {
      cpSync(legacy, current, { recursive: true });
      rmSync(legacy, { recursive: true, force: true });
    } else {
      throw error;
    }
  }
}

export function mintRunId(prefix) {
  const ts = Date.now();
  const rand = randomBytes(5).toString("hex");
  return `${prefix}-${ts}-${rand}`;
}

export function storeFor(target) {
  migrateLegacyStore(target);
  const root = resolve(target, STORE_DIR_NAME);
  return {
    target: resolve(target),
    root,
    storeName: STORE_DIR_NAME,
    legacyStoreName: LEGACY_STORE_DIR_NAME,
    runsDir: join(root, "runs"),
    // Deep reasoning context (a system-understanding pass between x-ray and the
    // threat model): modules, actors, trust boundaries, invariants. Context only —
    // no findings. threat-model-prepare feeds it to the threat-modeler.
    deepContextPath: join(root, "deep-context.json"),
    threatModelPath: join(root, "threat-model.json"),
    threatLeadsPath: join(root, "threat-leads.json"),
    threatIntelAppliedJsonPath: join(root, "threat-intel-applied.json"),
    threatIntelAppliedMdPath: join(root, "threat-intel-applied.md"),
    // Live CVE research + the invariants it distills, and the results of
    // checking those invariants against the code.
    threatIntelPath: join(root, "threat-intel.json"),
    threatIntelMdPath: join(root, "threat-intel.md"),
    invariantResultsPath: join(root, "invariant-results.json"),
    // Adversarial per-threat review (threat-hunt) + the canonical findings index
    // that downstream modules (verify / poc / chain-finder) consume.
    threatHuntPath: join(root, "threat-hunt.json"),
    // Scan-driven native / memory-safety review (systems-hunt). Verdicts promote
    // into the shared findings index too.
    systemsHuntPath: join(root, "systems-hunt.json"),
    // IRIS-style source→sink taint analysis (taint-analysis) — its own canonical
    // artifact; verdicts also promote into the shared findings index below.
    taintAnalysisPath: join(root, "taint-analysis.json"),
    // Variant hunt: siblings of confirmed findings (same bug class, other sites).
    // Verdicts promote into the shared findings index with source "variant-hunt".
    variantHuntPath: join(root, "variant-hunt.json"),
    // SAST: triaged semgrep hits promoted into the shared findings index
    // (source "sast"). Scanner hits are evidence; the agent triages before promotion.
    sastPath: join(root, "sast.json"),
    // Generated, test-driven Semgrep rules distilled from confirmed findings, plus
    // a manifest indexing them. These rules seed /variant-hunt and /sast re-runs.
    rulesDir: join(root, "rules"),
    semgrepRulesPath: join(root, "semgrep-rules.json"),
    // CodeQL/Joern synthesized-rule pack (the engines /semgrep-rule omits): the
    // per-engine rule files, a digest-attested manifest, and the run provenance.
    rulesCodeqlDir: join(root, "rules", "codeql"),
    rulesJoernDir: join(root, "rules", "joern"),
    rulePackManifestPath: join(root, "rules", "pack.json"),
    ruleSynthPath: join(root, "rule-synth.json"),
    // Dependency takeover/abandonment risk (supply-chain); change-focused review
    // (diff-review); and API-design footgun review (sharp-edges). Each promotes
    // verdicts into the shared findings index under its own source.
    supplyChainPath: join(root, "supply-chain.json"),
    diffReviewPath: join(root, "diff-review.json"),
    sharpEdgesPath: join(root, "sharp-edges.json"),
    findingsPath: join(root, "findings.json"),
    // Exploitability verification (verify, read-only reasoning) and empirical
    // proof-of-concept results (poc, sandbox-executed) — both attach their
    // outcome onto findings.json and persist a canonical artifact here.
    verifyPath: join(root, "verify.json"),
    pocPath: join(root, "poc.json"),
    // Memory-corruption exploitability assessment (mem-exploitability) — tiers +
    // mitigation posture; attaches an `exploitability` block onto findings.json.
    memExploitabilityPath: join(root, "mem-exploitability.json"),
    // PoC⁺ patch validation (/fix): generated patches validated in a sandbox
    // copy (stops the exploit + preserves function), attaching a `fix` block.
    fixPath: join(root, "fix.json"),
    // Prebuilt semantic indexes for the heavy backends (built async on consent).
    codeqlDbDir: join(root, "codeql-db"),
    joernCpgPath: join(root, "joern", "cpg.bin.zip"),
    dbBuildStatePath: join(root, "db-build-state.json"),
    validatedFindingsPath: join(root, "validated-findings.json"),
    findingsDbPath: join(root, "v2", "findings.sqlite3"),
    catalogsDir: join(root, "catalogs"),
    // Tool-boundary policy override + approval markers (trust plane). The
    // shipped default lives at the plugin root (policy.default.json); this is
    // the optional per-target override + the raw-query approval marker dir.
    policyPath: join(root, "policy.json"),
    approvalsDir: join(root, ".approvals"),
    // x-ray lives under .kuzushi/ alongside every other artifact (this plugin
    // keeps everything in one store dir rather than a top-level x-ray/).
    xRayDir: join(root, "x-ray")
  };
}

export function openRun(target, kind, runId = null) {
  const store = storeFor(target);
  const id = runId ?? mintRunId(`host-${kind}`);
  const runDir = join(store.runsDir, id);
  mkdirSync(runDir, { recursive: true });
  return {
    runId: id,
    runDir,
    relativeRunDir: relative(store.target, runDir),
    writeJson(name, value) {
      atomicWrite(join(runDir, name), `${JSON.stringify(value, null, 2)}\n`);
    },
    writeText(name, value) {
      atomicWrite(join(runDir, name), value.endsWith("\n") ? value : `${value}\n`);
    },
    finalize(result) {
      // Stamp provenance (toolchain/repo/scope/policy digests) onto every run
      // result unless a caller already supplied one. Guarded — provenance is
      // best-effort and must never break a finalize. Lazy import avoids any
      // load-order coupling with provenance.mjs (which reads this store).
      if (result && typeof result === "object" && !result.provenance) {
        try {
          result = { ...result, provenance: provenanceFor(target) };
        } catch {
          /* provenance unavailable — proceed without it */
        }
      }
      this.writeJson("result.json", result);
      return result;
    }
  };
}

// Atomic write: write to a sibling .tmp then rename. Same-fs in practice.
export function atomicWrite(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, content);
  renameSync(tmp, path);
}

// Common entry-point for host scripts that need a uniform "what artifacts are
// already on disk for this target" snapshot. Returns null for missing paths so
// downstream code can render "not present" without crashing.
export function artifactSnapshot(target) {
  const store = storeFor(target);
  const paths = {
    xRay: join(store.xRayDir, "x-ray.md"),
    entryPoints: join(store.xRayDir, "entry-points.md"),
    invariants: join(store.xRayDir, "invariants.md"),
    threatModel: store.threatModelPath,
    threatLeads: store.threatLeadsPath,
    threatIntel: store.threatIntelAppliedJsonPath,
    validatedFindings: store.validatedFindingsPath
  };
  return Object.fromEntries(
    Object.entries(paths).map(([key, path]) => [
      key,
      existsSync(path) ? { path, mtime: statSync(path).mtime.toISOString() } : null
    ])
  );
}

export function readJsonIfPresent(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

export function readRunResult(target, runId) {
  const store = storeFor(target);
  const path = join(store.runsDir, runId, "result.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

// Result shape emitted to stdout by every host script. Keeping this in one
// place lets cli.mjs and tests assert a stable envelope.
export function emitResult(result) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
