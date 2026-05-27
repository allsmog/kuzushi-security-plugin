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
import { hasContextRun, hasXray, hasThreatModel, hasThreatIntel, hasThreatHunt, hasCodeqlDb, hasJoernCpg } from "../scripts/lib/context-status.mjs";
import { readJsonIfPresent } from "../scripts/lib/artifact-store.mjs";
import { selectForTarget } from "../scripts/cmd/select-tooling.mjs";
import { markAutoAttempted } from "../scripts/cmd/install-tooling.mjs";
import { VENDOR_TOOLS } from "../scripts/lib/vendor-manifest.mjs";

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
    const state = readJsonIfPresent(join(VENDOR_DIR, ".install-state.json"));
    if (state?.autoAttempted) return;
    mkdirSync(VENDOR_DIR, { recursive: true });
    markAutoAttempted();
    const log = openSync(join(VENDOR_DIR, "install.log"), "a");
    const child = spawn(
      process.execPath,
      [INSTALL_TOOLING, "--target", cwd, "--json"],
      { detached: true, stdio: ["ignore", log, log] }
    );
    child.unref();
  } catch {
    // Never let auto-install break the session.
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

  reportState(cwd, result, {
    alreadyBuilt: status.built,
    builtAt: status.mtime,
    xray: hasXray(cwd),
    threatModel: hasThreatModel(cwd),
    threatIntel: hasThreatIntel(cwd),
    threatHunt: hasThreatHunt(cwd),
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

function reportState(cwd, result, { alreadyBuilt, builtAt, xray, threatModel, threatIntel, threatHunt, codeqlDb, joernCpg, tooling }) {
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
    `  codeql-db:    ${codeqlLine}`,
    `  joern-cpg:    ${joernLine}`,
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

  // Offer to build the heavy semantic indexes (codeql DB + joern CPG) early — they
  // power codeql/joern queries in threat-hunt/invariant-test, are slow, and build
  // in the BACKGROUND (never block the session). Offer once, before a build is
  // attempted (db-build.log present = attempted/in-progress).
  const hasSource = Object.entries(byLanguage).some(([l, c]) => l !== "Other" && Number(c) > 0);
  if (hasSource && !(codeqlDb.built && joernCpg.built) && !dbBuilding) {
    additionalContext +=
      `\n\nNo codeql database / joern CPG is built yet — these power deep semantic queries for ` +
      `/threat-hunt and /invariant-test. They're large and slow, so they build in the BACKGROUND ` +
      `(the session is NOT blocked). Ask the user with AskUserQuestion whether to build them now ` +
      `("Yes, build in background" / "No"). If Yes, run exactly:\n` +
      `    node "${BUILD_DATABASES}" --target "${cwd}" --which both --background --include-install\n` +
      `It returns immediately ({status:"started", logPath}); it installs the codeql/joern CLI first ` +
      `if missing (~1–3 GB) and writes progress to .kuzushi/db-build.log. Tell the user it's building ` +
      `and will be ready for codeql/joern queries once it finishes. If No, note /build-databases is available later.`;
  }

  // Tooling notes. Light, language-relevant tools (rust-analyzer/clangd/jdtls +
  // codegraph/gopls/gtags/semgrep) are being installed in the background on first
  // session; they'll be ready next session. Heavy backends (codeql/joern) are
  // never auto-downloaded — they're surfaced as a /install suggestion.
  const missingLsp = (tooling?.lsp ?? []).filter((s) => !s.installed);
  if (missingLsp.length) {
    additionalContext +=
      `\n\nLSP servers relevant to this repo but not yet present: ` +
      missingLsp.map((s) => s.name).join(", ") +
      `. The light ones auto-install in the background (vendor/install.log) and are ready ` +
      `next session; run /doctor for status. Mention only if the user asks about code intelligence.`;
  }
  const heavyMissing = relevantHeavyMissing(byLanguage);
  if (heavyMissing.length) {
    additionalContext +=
      `\n\nHeavy analysis backends relevant to this repo are NOT installed (too large to ` +
      `auto-download): ${heavyMissing.join(", ")}. Run /install ${heavyMissing[0]} ` +
      `(codeql ~1GB / joern ~2GB) to vendor it for deeper semantic queries.`;
  }
  additionalContext +=
    `\n\nCommands: /threat-model (build/rebuild PASTA model), /threat-intel (research CVEs), ` +
    `/threat-hunt (adversarial per-threat review → findings.json), /invariant-test (check CVE ` +
    `invariants vs code), /build-databases (codeql DB + joern CPG, async), /doctor (tooling status), ` +
    `/install (install tools).`;

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
