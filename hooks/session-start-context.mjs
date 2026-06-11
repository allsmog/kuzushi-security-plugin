#!/usr/bin/env node
// SessionStart hook: ensure repository context exists for the session's cwd and
// always report the state in chat.
//
// If a completed context run already exists, report that it's present (reading
// the existing context.json for counts). If not, build context now with the
// plugin's own builder (no external kuzushi binary) and report that it was just
// built.
//
// The report is delivered via hookSpecificOutput.additionalContext with a
// directive for Claude to print it verbatim. This renders as a normal (white)
// assistant message — unlike systemMessage, which the CLI always dims to grey.
//
// It also checks whether x-ray has been run. If not, the directive asks Claude
// to propose running the (deterministic) x-ray pass — which surfaces Claude
// Code's native Allow/Deny permission prompt — and paste the result on approval.
//
// Finally it checks whether a PASTA threat model exists. If not, the directive
// asks Claude to get a Yes/No from the user and, on Yes, launch the agent-driven
// threat-modeler (which builds it in phases and persists .kuzushi/threat-model.json).
//
// A SessionStart hook must never block the session: any failure is swallowed,
// reported as a systemMessage, and we still exit 0.

import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdirSync, openSync } from "node:fs";
import { spawn } from "node:child_process";
import { buildContext } from "../scripts/cmd/context-build.mjs";
import { hasContextRun, hasXray, hasThreatModel, hasThreatIntel, hasThreatHunt, hasSystemsHunt, hasVerify, hasPoc, hasMemExploitability, hasFix, hasChains, hasCodeqlDb, hasJoernCpg } from "../scripts/lib/context-status.mjs";

// CWEs that denote a memory-corruption class bug (mirrors mem-exploitability-prepare).
// A finding in this set (or from systems-hunt) is assessable by /mem-exploitability.
const MEMORY_CWES = new Set(["119","120","121","122","124","125","126","127","131","190","191","415","416","476","787","824"]);
function isMemoryFinding(f) {
  if (f.source === "systems-hunt") return true;
  const cwe = String(Array.isArray(f.cwe) ? f.cwe[0] : (f.cwe ?? "")).replace(/^CWE-/i, "").trim();
  return MEMORY_CWES.has(cwe);
}
import { readJsonIfPresent, storeFor } from "../scripts/lib/artifact-store.mjs";
import { selectForTarget } from "../scripts/cmd/select-tooling.mjs";
import { markAutoAttempted } from "../scripts/cmd/install-tooling.mjs";
import { VENDOR_TOOLS } from "../scripts/lib/vendor-manifest.mjs";
import { autoInstallAllowed, loadPolicy } from "../scripts/lib/policy.mjs";
import { commandInstalled } from "../scripts/lib/capabilities.mjs";
import { autoBuildDecision, effectiveAutoBuildSetting } from "../scripts/lib/auto-build.mjs";
import { installStarterPack } from "../scripts/cmd/install-starter-pack.mjs";

// Absolute paths resolved from this hook's own location so directives Claude
// runs need no env-var expansion in its shell.
const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const XRAY_SCRIPT = join(PLUGIN_ROOT, "scripts", "cmd", "x-ray.mjs");
const THREAT_MODEL_PREPARE = join(PLUGIN_ROOT, "scripts", "cmd", "threat-model-prepare.mjs");
const THREAT_INTEL_PREPARE = join(PLUGIN_ROOT, "scripts", "cmd", "threat-intel-prepare.mjs");
const INSTALL_TOOLING = join(PLUGIN_ROOT, "scripts", "cmd", "install-tooling.mjs");
const BUILD_DATABASES = join(PLUGIN_ROOT, "scripts", "cmd", "build-databases.mjs");
const VENDOR_DIR = join(PLUGIN_ROOT, "vendor");

// Kick off a one-time, background, language-gated install of the LIGHT tools.
// Marker is written BEFORE spawning so a slow child never causes a re-spawn.
// Heavy tools (codeql/joern) are never auto-installed — see reportState.
function autoInstallLightTools(cwd) {
  try {
    if (!autoInstallAllowed(cwd)) return;
    const state = readJsonIfPresent(join(VENDOR_DIR, ".install-state.json"));
    if (state?.autoAttempted) return;
    mkdirSync(VENDOR_DIR, { recursive: true });
    markAutoAttempted();
    const log = openSync(join(VENDOR_DIR, "install.log"), "a");
    const child = spawn(
      process.execPath,
      [INSTALL_TOOLING, "--target", cwd, "--json", "--approved"],
      { detached: true, stdio: ["ignore", log, log] }
    );
    child.unref();
  } catch {
    // Never let auto-install break the session.
  }
}

// Deep-by-default: when the CodeQL/Joern CLI is already installed (so the build
// is a free, local operation — no network), kick the DB/CPG build in the
// background at session start instead of waiting for the user to opt in. This is
// the single biggest recall lever: interprocedural taint needs a built index, and
// leaving it opt-in means most runs degrade to same-file linking. Policy-gated
// (ci-locked → off; CLI absent → the offer prompt, since an install needs
// approval). Spawns at most once per target (db-build.log presence = attempted).
// Returns the decision so the report can phrase it; never throws.
function autoBuildDatabases(cwd, byLanguage) {
  try {
    const policy = loadPolicy(cwd);
    const setting = effectiveAutoBuildSetting(policy);
    const sourcePresent = Object.entries(byLanguage ?? {}).some(([l, c]) => l !== "Other" && Number(c) > 0);
    const store = storeFor(cwd);
    const buildLog = join(store.root, "db-build.log");
    const decision = autoBuildDecision({
      setting,
      sourcePresent,
      dbBuilding: existsSync(buildLog),
      codeqlCli: commandInstalled("codeql"),
      codeqlDbBuilt: hasCodeqlDb(cwd).built,
      joernCli: commandInstalled("joern"),
      joernCpgBuilt: hasJoernCpg(cwd).built
    });
    if (!decision.anyBuild) return decision;
    // Local-only build (CLIs are present): no --include-install, so no network.
    mkdirSync(store.root, { recursive: true });
    const log = openSync(buildLog, "a");
    const child = spawn(
      process.execPath,
      [BUILD_DATABASES, "--target", cwd, "--which", decision.which, "--background"],
      { detached: true, stdio: ["ignore", log, log] }
    );
    child.unref();
    // Install the curated starter queries so they're ready when the DB/CPG is —
    // the other half of deep-by-default. Idempotent (upserts by ruleId); never
    // let it break the session.
    try { installStarterPack(cwd); } catch { /* starter pack is best-effort */ }
    return { ...decision, started: true };
  } catch {
    return null; // never let auto-build break the session
  }
}

// Heavy vendor tools (codeql/joern) relevant to the detected languages but not
// yet vendored — surfaced as a /install suggestion, never auto-downloaded.
function relevantHeavyMissing(byLanguage) {
  const detected = new Set(Object.entries(byLanguage ?? {})
    .filter(([l, c]) => l !== "Other" && Number(c) > 0).map(([l]) => l));
  return Object.entries(VENDOR_TOOLS)
    .filter(([, t]) => t.sizeClass === "heavy")
    .filter(([, t]) => t.languages.some((l) => detected.has(l)))
    .filter(([name]) => !existsSync(join(VENDOR_DIR, "bin", name)))
    .map(([name]) => name);
}

// Summarize the shared findings index for the report + the verify/poc offers.
// All verify/poc surfacing is gated on findings actually existing — no findings,
// nothing to verify or prove. `verifiable` = an open / trace-needed finding with
// no verification block yet; `pocPending` = a PoC-ready finding not yet proven.
function readFindingsStatus(cwd) {
  const doc = readJsonIfPresent(storeFor(cwd).findingsPath);
  const findings = doc?.findings ?? [];
  if (!findings.length) return { present: false, total: 0, verifiable: false, pocPending: false, memAssessable: false, variantSeedable: false, fixable: false, fixApplyable: false, chainable: false, pathSolvable: false };
  const byStatus = doc.summary?.byStatus ?? {};
  return {
    present: true,
    total: findings.length,
    open: byStatus.open ?? 0,
    confirmed: byStatus.confirmed ?? 0,
    proven: byStatus.proven ?? 0,
    verifiable: findings.some((f) => (f.status === "open" || f.verdict === "needs-active-agent-trace") && !f.verification),
    pocPending: findings.some((f) => f.verification?.pocReady && !f.poc),
    // A confirmed/proven finding can seed a /variant-hunt for siblings.
    variantSeedable: findings.some((f) => f.status === "confirmed" || f.status === "proven"),
    // A memory-corruption finding that hasn't been characterized yet ⇒ /mem-exploitability applies.
    memAssessable: findings.some((f) => isMemoryFinding(f) && !f.exploitability),
    // A confirmed/proven finding without a fix block ⇒ /fix can generate + PoC⁺-validate a patch.
    fixable: findings.some((f) => (f.status === "proven" || f.status === "confirmed") && !f.fix),
    // A PoC⁺-validated patch not yet applied ⇒ /fix can apply it behind approval.
    fixApplyable: findings.some((f) => f.fix?.verdict === "validated" && f.status !== "remediated"),
    // ≥2 live findings ⇒ /chain can look for cross-finding attack chains.
    chainable: findings.filter((f) => !["reviewed", "noise"].includes(f.status)).length >= 2,
    // A finding /verify left inconclusive (or needs an active trace) ⇒ /path-solve.
    pathSolvable: findings.some((f) => f.verification?.verdict === "inconclusive" ||
      f.status === "needs-trace" || f.verdict === "needs-active-agent-trace")
  };
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    // No stdin attached (e.g. manual run without a pipe): resolve empty.
    if (process.stdin.isTTY) resolve("");
  });
}

function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

async function run() {
  const raw = await readStdin();
  let cwd = process.cwd();
  try {
    if (raw.trim()) {
      const parsed = JSON.parse(raw);
      if (typeof parsed.cwd === "string" && parsed.cwd) cwd = parsed.cwd;
    }
  } catch {
    // Malformed stdin: fall back to process.cwd() rather than aborting.
  }

  const status = hasContextRun(cwd);
  // Pull the artifact for whichever run we report: the existing one if present,
  // or a freshly built one otherwise. Both files share the context.json shape.
  const result = status.built
    ? readJsonIfPresent(join(status.runDir, "context.json")) ?? { runId: status.runId, inventory: {}, componentHints: [] }
    : buildContext(cwd);

  // Compute relevant LSP/MCP tooling from the detected languages and persist
  // tooling-selection.json. Never let a selection hiccup break the report.
  let tooling = null;
  try {
    tooling = selectForTarget(cwd);
  } catch {
    tooling = null;
  }

  // One-time background install of the light, language-relevant tools.
  autoInstallLightTools(cwd);
  // Deep-by-default: auto-build the CodeQL DB / Joern CPG when the CLI is already
  // present and policy permits, so deep interprocedural queries are ready without
  // an opt-in. Writes .kuzushi/db-build.log, which the report keys on below.
  autoBuildDatabases(cwd, result.inventory?.byLanguage ?? {});

  reportState(cwd, result, {
    alreadyBuilt: status.built,
    builtAt: status.mtime,
    xray: hasXray(cwd),
    threatModel: hasThreatModel(cwd),
    threatIntel: hasThreatIntel(cwd),
    threatHunt: hasThreatHunt(cwd),
    systemsHunt: hasSystemsHunt(cwd),
    verify: hasVerify(cwd),
    poc: hasPoc(cwd),
    memExploit: hasMemExploitability(cwd),
    fix: hasFix(cwd),
    chains: hasChains(cwd),
    findings: readFindingsStatus(cwd),
    codeqlDb: hasCodeqlDb(cwd),
    joernCpg: hasJoernCpg(cwd),
    tooling
  });
  process.exit(0);
}

// Full language breakdown, sorted by count descending. "Other" is kept but
// pushed to the end so it never crowds out a named language.
function languageLines(byLanguage) {
  const entries = Object.entries(byLanguage).sort((a, b) => {
    if (a[0] === "Other") return 1;
    if (b[0] === "Other") return -1;
    return b[1] - a[1];
  });
  if (!entries.length) return ["    (none detected)"];
  return entries.map(([lang, count]) => `    ${lang.padEnd(12)} ${count}`);
}

function componentLines(hints) {
  if (!hints?.length) return ["    (none detected)"];
  return hints.map((hint) => `    ${hint.marker} → ${hint.role} (${hint.count})`);
}

// Tooling relevant to the detected languages. ✓ = binary on PATH, ✗ = missing.
function toolingLines(tooling) {
  if (!tooling) return ["    (selection unavailable)"];
  const lsp = tooling.lsp.length
    ? tooling.lsp.map((s) => `${s.name} ${s.installed ? "✓" : "✗"}`).join("   ")
    : "(none relevant)";
  const mcp = tooling.mcp.length
    ? tooling.mcp.map((b) => `${b.name} ${b.installed ? "✓" : "✗"}${b.selfGating ? " (self-gating)" : ""}`).join("   ")
    : "(none relevant)";
  return [`    LSP:  ${lsp}`, `    MCP:  ${mcp}`];
}

// The single most useful next command for where the user is in the 4-phase flow
// (MAP → HUNT → CONFIRM → FIX·SHIP). Returns null while an earlier consent-gated
// step (x-ray / threat model) is still pending — those blocks below already drive
// the next action. Keeping this to ONE recommendation is the point: 40 commands is
// overwhelming, a phase map plus one obvious next step is not.
function recommendedNext({ xray, threatModel, findings, hasReport }) {
  if (!xray.built || !threatModel.built) return null; // the offers below handle setup
  if (!findings.present) return { cmd: "/sweep", why: "the map is built — hunt the whole repo in one pass (it verifies findings as it goes)" };
  if (findings.verifiable) return { cmd: "/verify", why: "there are open findings — confirm which are actually exploitable" };
  if (findings.pocPending) return { cmd: "/poc", why: "verified findings are PoC-ready — prove them in a sandbox" };
  if ((findings.confirmed || findings.proven) && !hasReport) return { cmd: "/report", why: "you have confirmed findings — render the prioritized report to triage and share" };
  if (findings.fixable) return { cmd: "/fix", why: "confirmed/proven findings can be patched and PoC⁺-validated" };
  return { cmd: "/report", why: "render the current findings into a prioritized, shareable report" };
}

function reportState(cwd, result, { alreadyBuilt, builtAt, xray, threatModel, threatIntel, threatHunt, systemsHunt, verify, poc, memExploit, fix, chains, findings, codeqlDb, joernCpg, tooling }) {
  let policy = null;
  try { policy = loadPolicy(cwd).effective; } catch { policy = null; }
  const totalFiles = result.inventory?.totalFiles ?? 0;
  const byLanguage = result.inventory?.byLanguage ?? {};
  const hints = result.componentHints ?? [];
  const relRunDir = `.kuzushi/runs/${result.runId}`;
  const statusLine = alreadyBuilt
    ? `already present (built ${builtAt ?? "earlier"})`
    : "built just now";
  const xrayLine = xray.built
    ? `present (.kuzushi/x-ray/x-ray.md, built ${xray.mtime})`
    : "not run yet";
  const threatLine = threatModel.built
    ? `present (.kuzushi/threat-model.json, built ${threatModel.mtime})`
    : "not run yet";
  const intelLine = threatIntel.built
    ? `present (.kuzushi/threat-intel.json, built ${threatIntel.mtime})`
    : "not run yet";
  const huntLine = threatHunt.built
    ? `present (.kuzushi/threat-hunt.json, built ${threatHunt.mtime})`
    : "not run yet";
  const systemsLine = systemsHunt.built
    ? `present (.kuzushi/systems-hunt.json, built ${systemsHunt.mtime})`
    : "not run yet";
  const findingsLine = findings.present
    ? `${findings.total} (${findings.open ?? 0} open, ${findings.confirmed ?? 0} confirmed, ${findings.proven ?? 0} proven)`
    : "none yet";
  // verify/poc lines are only meaningful once findings exist.
  const verifyLine = !findings.present ? "—" : (verify.built ? `present (.kuzushi/verify.json, built ${verify.mtime})` : "not run yet");
  const pocLine = !findings.present ? "—" : (poc.built ? `present (.kuzushi/poc.json, built ${poc.mtime})` : "not run yet");
  // mem-exploit only meaningful once a memory-corruption finding exists.
  const memExploitLine = !findings.memAssessable && !memExploit.built ? "—" : (memExploit.built ? `present (.kuzushi/mem-exploitability.json, built ${memExploit.mtime})` : "not run yet");
  // fix only meaningful once there's a fixable (confirmed/proven) finding.
  const fixLine = !findings.fixable && !fix.built ? "—" : (fix.built ? `present (.kuzushi/fix.json, built ${fix.mtime})` : "not run yet");
  // chain only meaningful once ≥2 live findings exist.
  const chainLine = !findings.chainable && !chains.built ? "—" : (chains.built ? `present (.kuzushi/chains.json, built ${chains.mtime})` : "not run yet");
  const dbBuilding = existsSync(join(cwd, ".kuzushi", "db-build.log"));
  const codeqlLine = codeqlDb.built ? `present (${(codeqlDb.languages ?? []).join(", ")})` : (dbBuilding ? "building…" : "not built");
  const joernLine = joernCpg.built ? "present (.kuzushi/joern/cpg.bin.zip)" : (dbBuilding ? "building…" : "not built");

  // Human-readable report. Rendered by Claude as a fenced code block so the
  // column alignment survives and it shows in normal (white) text.
  const report = [
    `kuzushi context — ${cwd}`,
    `  status:    ${statusLine}`,
    `  artifacts: ${relRunDir}/context.json`,
    `  files:     ${totalFiles}`,
    `  languages:`,
    ...languageLines(byLanguage),
    `  components:`,
    ...componentLines(hints),
    `  x-ray:        ${xrayLine}`,
    `  threat-model: ${threatLine}`,
    `  threat-intel: ${intelLine}`,
    `  threat-hunt:  ${huntLine}`,
    `  systems-hunt: ${systemsLine}`,
    `  findings:     ${findingsLine}`,
    `  verify:       ${verifyLine}`,
    `  poc:          ${pocLine}`,
    `  mem-exploit:  ${memExploitLine}`,
    `  fix:          ${fixLine}`,
    `  chain:        ${chainLine}`,
    `  codeql-db:    ${codeqlLine}`,
    `  joern-cpg:    ${joernLine}`,
    `  policy:       ${policy?.activeProfile ?? "unknown"} (raw-query: ${policy?.mcp?.rawQuery ?? "unknown"}, hook-errors: ${policy?.guardrails?.onHookError ?? "unknown"}, auto-install: ${policy?.install?.autoInstallLightTools ?? "unknown"})`,
    `  tooling (✓ installed / ✗ missing):`,
    ...toolingLines(tooling)
  ].join("\n");

  // Deliver the report two ways: systemMessage shows it immediately at startup
  // (dimmed grey — the only immediate channel), and additionalContext carries a
  // directive so Claude restates it in normal white text on the first turn.
  let additionalContext =
    `The kuzushi SessionStart hook ${alreadyBuilt ? "found existing" : "just built"} ` +
    `repository context for this session's working directory. On your first turn, ` +
    `display the following report to the user verbatim, inside a fenced code block, ` +
    `and add no commentary unless asked:\n\n${report}`;

  // ONE clear next action for where they are in the 4-phase flow (the phase map at
  // the very end gives the full breadth). This is the antidote to command overwhelm:
  // a single obvious step, not a menu of 40.
  const hasReport = existsSync(join(storeFor(cwd).root, "report.md"));
  const nextStep = recommendedNext({ xray, threatModel, findings, hasReport });
  if (nextStep) {
    additionalContext +=
      `\n\nAfter the report, surface exactly ONE recommended next step to the user: ` +
      `\`${nextStep.cmd}\` — ${nextStep.why}. Present it as the suggested next command; don't auto-run it.`;
  }

  // When x-ray hasn't been run, ask Claude to propose running it. Running the
  // command surfaces the native Allow/Deny permission prompt (the consent gate).
  if (!xray.built) {
    additionalContext +=
      `\n\nX-ray analysis has NOT been run for this repository. After showing the ` +
      `report, run it now by invoking exactly this command (the user will see a ` +
      `permission prompt — that is expected and is how they consent):\n` +
      `    node "${XRAY_SCRIPT}" --target "${cwd}"\n` +
      `If the user approves and it completes, read ${cwd}/.kuzushi/x-ray/x-ray.md and paste ` +
      `its contents into the chat verbatim inside a fenced code block. If the user ` +
      `denies, acknowledge it and continue without x-ray.`;
  }

  // Deep-context — a reasoning pass between x-ray and the threat model. Surface it
  // once x-ray exists and neither deep-context nor a threat model has been built.
  const deepContextPresent = existsSync(storeFor(cwd).deepContextPath);
  if (xray.built && !deepContextPresent && !threatModel.built) {
    additionalContext +=
      `\n\nx-ray is present but no deep-context model has been built. /deep-context is available: a ` +
      `deeper reasoning pass (read key code line-by-line → modules, entry points, actors, trust ` +
      `boundaries, and system invariants → .kuzushi/deep-context.json) that grounds the threat model. ` +
      `It's context only (no vuln-finding). Mention it as an optional step before /threat-model; don't auto-run it.`;
  }

  // When no threat model exists, ask the user's permission (Yes/No), and only on
  // Yes launch the agent-driven PASTA threat-modeler. x-ray (a scope input) is
  // handled above first.
  if (!threatModel.built) {
    additionalContext +=
      `\n\nNo PASTA threat model exists for this repository. After the report and any ` +
      `x-ray step, ask the user with the AskUserQuestion tool whether to build the PASTA ` +
      `threat model now (options: "Yes, build it" / "No, skip"). If they choose Yes, ` +
      `launch the "threat-modeler" agent with the Task tool (subagent_type the ` +
      `threat-modeler agent provided by this plugin) and pass it this prompt:\n` +
      `    Build a PASTA threat model for the target repository "${cwd}". Start by ` +
      `running: node "${THREAT_MODEL_PREPARE}" --target "${cwd}" — then follow your ` +
      `phase workflow (S1→S4), write each pasta-s*.json, and run the assembleCommand it ` +
      `prints. Report the summary + ASCII data-flow diagram when done.\n` +
      `When the agent finishes, post to the user: (1) a brief summary of what was done ` +
      `(threat counts by category + top threats, from ${cwd}/.kuzushi/threat-model.json), ` +
      `and (2) the ASCII data-flow diagram from ${cwd}/.kuzushi/threat-model-dfd.txt, ` +
      `pasted verbatim inside a fenced code block. If they choose No, acknowledge and continue.`;
  }

  // Threat-intel offer — only once a threat model exists (it cross-references it).
  // Yes/No, then launch the research agent. If intel already exists, point at /invariant-test.
  if (threatModel.built && !threatIntel.built) {
    additionalContext +=
      `\n\nA threat model exists but no CVE threat-intel has been gathered. After the report, ` +
      `ask the user with AskUserQuestion whether to research threat intel now (options: ` +
      `"Yes, research CVEs" / "No, skip") — note it uses live web search and may take a bit. ` +
      `If Yes, launch the "threat-intel-researcher" agent (Task tool) with this prompt:\n` +
      `    Research critical/high CVEs for "${cwd}" (this stack + similar apps). Start by ` +
      `running: node "${THREAT_INTEL_PREPARE}" --target "${cwd}" — then research, write the ` +
      `intel-*.json stage files (incl. invariants), and run the assembleCommand it prints.\n` +
      `When done, summarize the top applicable CVEs + invariants and mention that ` +
      `/invariant-test can now check those invariants against the code. If No, continue.`;
  } else if (threatIntel.built) {
    additionalContext +=
      `\n\nThreat-intel is present (.kuzushi/threat-intel.json). You can run /invariant-test to ` +
      `verify its CVE-derived invariants against the code.`;
  }

  // Threat-hunt availability — once a threat model exists. Not an offer (it's a
  // heavy, on-demand adversarial review); just note the command.
  if (threatModel.built && !threatHunt.built) {
    additionalContext +=
      `\n\nA threat model exists — /threat-hunt is available: an adversarial per-threat review ` +
      `(attacker capabilities → source/sink → bypass every guard → verdict) that promotes ` +
      `findings into .kuzushi/findings.json. Mention it if the user wants to go deeper; don't auto-run it.`;
  }

  // Systems-hunt availability — only worth surfacing on native / memory-unsafe
  // code (it finds little in pure web stacks). On-demand note, not an offer.
  const systemsLangs = ["C", "C++", "Rust"].filter((l) => Number(byLanguage[l] ?? 0) > 0);
  if (systemsLangs.length && !systemsHunt.built) {
    additionalContext +=
      `\n\nThis repo has systems/native code (${systemsLangs.join(", ")}) — /systems-hunt is ` +
      `available: a native / parser / memory-safety review (loadLibrary/JNI, memcpy/Unsafe/gets, ` +
      `archive parsers, deserialization) that promotes findings into .kuzushi/findings.json. ` +
      `Mention it for deeper memory-safety coverage; don't auto-run it.`;
  }

  // (Breadth producers — /supply-chain, /sharp-edges, /crypto-review, /diff-review,
  // etc. — are surfaced by phase in the phase map at the end, not as a wall here.)

  // Verify / poc are only surfaced when the findings index has findings — no
  // findings, nothing to verify or prove. Both are on-demand notes (not auto-run);
  // /poc in particular builds and EXECUTES harnesses, so never launch it unprompted.
  if (findings.present && findings.verifiable) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has open findings — /verify is available: it reconstructs each ` +
      `finding's source→sink, builds a concrete trigger, and assigns an exploitability verdict ` +
      `(confirmed-exploitable / not-exploitable / inconclusive) with a PoC sketch, attaching a ` +
      `verification block onto each finding. Mention it if the user wants to confirm exploitability; don't auto-run it.`;
  }
  if (findings.present && findings.pathSolvable) {
    additionalContext +=
      `\n\nSome findings are inconclusive / need an active trace — /path-solve is available: it extracts the ` +
      `guard predicate between source and sink and solves it into a concrete reaching input (Z3 / CrossHair ` +
      `if installed, else LLM reasoning), attaching a pathSolution block that feeds /verify + /fuzz. Heuristic, ` +
      `not a proof; mention it for hard-to-reach sinks, don't auto-run it.`;
  }
  if (findings.present && findings.pocPending) {
    additionalContext +=
      `\n\nSome findings are PoC-ready (verified confirmed-exploitable / inconclusive) — /poc is available: ` +
      `it builds a minimal harness per finding and RUNS it in a sandbox (Docker --network none, else a gated ` +
      `local run) to empirically prove the bug. It executes code, so only run it when the user explicitly asks; never auto-run it.`;
  }
  if (findings.present && (findings.confirmed || findings.proven)) {
    additionalContext +=
      `\n\nConfirmed/proven findings can seed /fuzz: it creates a local fuzz campaign plan and harness ` +
      `workspace, executes declared harnesses offline, dedupes crashes, records minimization, and only ` +
      `advances empirical crash/sanitizer evidence to proven. ` +
      `Mention it for parser/native/library targets; don't auto-run it.`;
  }
  // mem-exploitability — surface when there's a memory-corruption finding not yet
  // assessed. Assessment only (tiers + mitigation posture + remediation, no payloads).
  if (findings.present && findings.memAssessable && !memExploit.built) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has memory-corruption finding(s) — /mem-exploitability is available: ` +
      `for each, it works the analysis phases (vuln shape → control/offset plausibility → input constraints → ` +
      `mitigation posture: NX/PIE/canary/RELRO/FORTIFY from build flags + read-only binary inspection) and ` +
      `assigns an exploitability tier (crash-only / dos / info-leak / control-flow-hijack-plausible / ` +
      `likely-code-exec) + remediation, attaching an exploitability block onto each finding. It's ` +
      `ASSESSMENT only (no exploit payloads / mitigation bypasses). Mention it for memory-safety triage; don't auto-run it.`;
  }

  // variant-hunt — surface once a confirmed/exploitable finding exists to seed it.
  // On-demand note, not an offer.
  if (findings.present && findings.variantSeedable) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has confirmed / exploitable finding(s) — /variant-hunt is available: ` +
      `for each as a seed, it sweeps the repo for OTHER sites with the same bug class (exact-match → ` +
      `generalize) and promotes the siblings into findings.json with refId variant-of:<seed>. Mention it ` +
      `to catch copy-paste recurrences of a known bug; don't auto-run it. /semgrep-rule can also distill ` +
      `a confirmed finding into a reusable Semgrep rule under .kuzushi/rules/.`;
  }

  // /fix — surface once a confirmed/proven finding exists. It GENERATES code and
  // EXECUTES harnesses, and can write the tree behind explicit approval — never auto-run.
  if (findings.present && findings.fixable && !fix.built) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has confirmed / proven finding(s) — /fix is available: it root-causes each bug, ` +
      `generates a minimal defensive unified-diff patch, and PoC⁺-validates it in a sandbox COPY (re-runs the ` +
      `existing PoC expecting NO crash, plus functional and supported semantic-oracle checks) — a patch is "validated" only if all ` +
      `required gates pass. It never touches your working tree until you explicitly approve ` +
      `the apply step (one finding at a time). It generates code and executes harnesses, so only run it when the user asks; don't auto-run it.`;
  } else if (findings.present && findings.fixApplyable) {
    additionalContext +=
      `\n\nSome findings have a PoC⁺-validated patch not yet applied — /fix's apply step can write it to the working ` +
      `tree behind an explicit Allow/Deny prompt (with a rollback command). Only run on the user's request.`;
  }

  // /report — the human-facing deliverable. Surface whenever findings exist; it
  // ranks "fix first" and renders chains/coverage/provenance. Read-only rendering.
  if (findings.present) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has findings — /report renders them into a prioritized, human-facing ` +
      `security report (.kuzushi/report.md; add "html" for report.html): a "fix first" ranking by ` +
      `severity × proof state × exploitability × blast radius, plus attack chains, coverage, and provenance. ` +
      `It's the deliverable to read/share (vs. /export-sarif for CI). Read-only; mention it whenever the ` +
      `user wants a summary or asks "what should I fix first".`;
  }

  // /chain — surface once ≥2 live findings exist to reason over. On-demand note.
  if (findings.present && findings.chainable && !chains.built) {
    additionalContext +=
      `\n\n.kuzushi/findings.json has multiple live findings — /chain is available: it reasons over them for ` +
      `cross-finding attack chains (precondition → pivot → impact, e.g. an auth bypass that escalates an SSRF to ` +
      `internal RCE) and attaches a chains ref onto each member (status unchanged). An analysis overlay, not a ` +
      `combined exploit. Mention it to surface compounded impact; don't auto-run it.`;
  }

  // Offer to build the heavy semantic indexes (codeql DB + joern CPG) early — they
  // power codeql/joern queries in threat-hunt/invariant-test, are slow, and build
  // in the BACKGROUND (never block the session). Offer once, before a build is
  // attempted (db-build.log present = attempted/in-progress).
  const hasSource = Object.entries(byLanguage).some(([l, c]) => l !== "Other" && Number(c) > 0);
  if (hasSource && !joernCpg.built && !dbBuilding) {
    additionalContext +=
      `\n\nNo deep semantic index is built yet — these power interprocedural queries for /threat-hunt, ` +
      `/taint-analysis and /invariant-test. **Joern is the primary backend** (Apache-2.0, works on private ` +
      `code, language-agnostic). It's large/slow so it builds in the BACKGROUND (the session is NOT blocked). ` +
      `Ask the user with AskUserQuestion whether to build it now ("Yes, build in background" / "No"). If Yes, run exactly:\n` +
      `    node "${BUILD_DATABASES}" --target "${cwd}" --which joern --background --include-install\n` +
      `It returns immediately ({status:"started", logPath}) and writes progress to .kuzushi/db-build.log. ` +
      `CodeQL is an OPTIONAL accelerator (higher precision, but proprietary — only licensed for public repos / ` +
      `GitHub Advanced Security); if this is a public repo or you have GHAS, add it with ` +
      `\`--which both\` instead. If No, note /build-databases is available later.`;
  }

  // Tooling notes. Light, language-relevant tools (rust-analyzer/clangd/jdtls +
  // codegraph/gopls/gtags/semgrep) are being installed in the background on first
  // session; they'll be ready next session. Heavy backends (codeql/joern) are
  // never auto-downloaded — they're surfaced as a /install suggestion.
  const missingLsp = (tooling?.lsp ?? []).filter((s) => !s.installed);
  if (missingLsp.length) {
    const autoInstall = policy?.install?.autoInstallLightTools === true || policy?.install?.autoInstallLightTools === "allow";
    additionalContext +=
      `\n\nLSP servers relevant to this repo but not yet present: ` +
      missingLsp.map((s) => s.name).join(", ") +
      (autoInstall
        ? `. The light ones auto-install in the background (vendor/install.log) and are ready next session; run /doctor for status.`
        : `. Auto-install is disabled by the active policy profile; run /install explicitly if needed.`) +
      ` Mention only if the user asks about code intelligence.`;
  }
  // Surface heavy backends Joern-first: it's the primary (open, unconditional);
  // CodeQL is an opt-in accelerator with a license caveat.
  const heavyMissing = relevantHeavyMissing(byLanguage)
    .sort((a, b) => (a === "joern" ? -1 : b === "joern" ? 1 : 0));
  if (heavyMissing.length) {
    const primary = heavyMissing.includes("joern") ? "joern" : heavyMissing[0];
    additionalContext +=
      `\n\nOptional analysis backends relevant to this repo are NOT installed (opt-in): ` +
      `${heavyMissing.join(", ")}. **Joern is the recommended primary** (Apache-2.0, ~2GB, works on ` +
      `private code) — run /install ${primary} to add it. CodeQL (~1GB) gives higher-precision flows ` +
      `but is proprietary and only licensed for public repos / GitHub Advanced Security, so add it only ` +
      `if that applies. (z3 / crosshair are small concolic solvers for /path-solve.)`;
  }
  // Phase map — the antidote to "40 commands". Only the 8 tier-1 commands are typeable
  // (in the / menu); the "+" items are NOT separate commands — they run inside their
  // phase (sweep picks hunters by language; verify routes by finding-type) or when the
  // user asks in plain language. Shown verbatim so the column alignment survives.
  additionalContext +=
    `\n\nFinally, to keep the command surface from overwhelming the user, show them this phase map ` +
    `verbatim inside a fenced code block (it is column-aligned). Most reviews need only two commands — ` +
    `/sweep then /report:\n\n` +
    `kuzushi — security review in 4 phases   (only the shown /commands are typeable; "+" runs inside the phase or on request)\n` +
    `  1 MAP        /threat-model     + deep-context · code-graph · dfd · threat-intel · invariant-test   (x-ray auto-runs)\n` +
    `  2 HUNT       /sweep            + taint · authz · logic-hunt · crypto · sharp-edges · systems · iac · supply-chain · sast · threat-hunt · binary-recon · traffic-map\n` +
    `                                   (/sweep selects these by language; or ask: "do an authz review")\n` +
    `  3 CONFIRM    /verify  /poc     + fuzz · path-solve · mem-exploitability   (/verify routes each finding to its proof path)\n` +
    `  4 FIX·SHIP   /fix  /report     + chain · variant-hunt · export-sarif · semgrep-rule · rule-synth\n` +
    `  entry  /diff-review (review a PR)     setup  /doctor (+ install · build-databases)\n\n` +
    `Happy path: /sweep (find + verify across the whole repo) → /report (prioritized, shareable report). ` +
    `The "+" tools aren't commands to type — they run inside their phase or when you ask for them.`;

  emit({
    systemMessage: report,
    hookSpecificOutput: { hookEventName: "SessionStart", additionalContext }
  });
}

run().catch((error) => {
  emit({
    systemMessage: `kuzushi: context check failed (${error?.message ?? error}). Continuing without it.`
  });
  process.exit(0);
});
