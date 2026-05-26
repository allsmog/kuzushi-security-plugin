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
// A SessionStart hook must never block the session: any failure is swallowed,
// reported as a systemMessage, and we still exit 0.

import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildContext } from "../scripts/cmd/context-build.mjs";
import { hasContextRun, hasXray } from "../scripts/lib/context-status.mjs";
import { readJsonIfPresent } from "../scripts/lib/artifact-store.mjs";

// Absolute path to the ported x-ray CLI, resolved from this hook's own location
// so the directive Claude runs needs no env-var expansion in its shell.
const XRAY_SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "cmd", "x-ray.mjs");

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

  reportState(cwd, result, {
    alreadyBuilt: status.built,
    builtAt: status.mtime,
    xray: hasXray(cwd)
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

function reportState(cwd, result, { alreadyBuilt, builtAt, xray }) {
  const totalFiles = result.inventory?.totalFiles ?? 0;
  const byLanguage = result.inventory?.byLanguage ?? {};
  const hints = result.componentHints ?? [];
  const relRunDir = `.kuzushi/runs/${result.runId}`;
  const statusLine = alreadyBuilt
    ? `already present (built ${builtAt ?? "earlier"})`
    : "built just now";
  const xrayLine = xray.built
    ? `present (x-ray/x-ray.md, built ${xray.mtime})`
    : "not run yet";

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
    `  x-ray:     ${xrayLine}`
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
      `If the user approves and it completes, read ${cwd}/x-ray/x-ray.md and paste ` +
      `its contents into the chat verbatim inside a fenced code block. If the user ` +
      `denies, acknowledge it and continue without x-ray.`;
  }

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
