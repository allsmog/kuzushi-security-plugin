// The single LLM integration point of the eval harness.
//
// kuzushi's agents are prose interpreted by a Claude session — there is no
// programmatic agent runner. So the ONLY faithful way to test the real deep-scanner
// / verifier is to spawn a real, fresh `claude -p` session that plays the forked
// agent: its system prompt is the agent's own .md, it gets the prep + the repo, and
// it writes its draft exactly as the live skill's forked agent would. The harness
// runs the deterministic prepare/finalize itself (same boundary the SKILL.md uses).
//
// Everything fragile about the LLM (cost, flakiness, timeouts, the bypass-permission
// headless path) is isolated here. Verified working: `claude -p
// --dangerously-skip-permissions --model sonnet --output-format json` runs headless
// and writes files; `--plugin-dir` loads the MCP tools but does NOT export
// $CLAUDE_PLUGIN_ROOT to Bash — so we pass the plugin path into the prompt.

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";

// Strip a leading YAML frontmatter block so the system prompt is clean instructions.
function agentBody(agentMdPath) {
  const raw = readFileSync(agentMdPath, "utf8");
  const m = raw.match(/^---\n[\s\S]*?\n---\n?/);
  return m ? raw.slice(m[0].length).trim() : raw.trim();
}

function parseResult(stdout) {
  try {
    const d = JSON.parse(stdout);
    return { cost: Number(d.total_cost_usd) || 0, result: d.result ?? "", isError: Boolean(d.is_error), turns: d.num_turns };
  } catch {
    return { cost: 0, result: "", isError: true, turns: null };
  }
}

// Run one forked agent headlessly. Resolves after the process exits; the agent's
// deliverable is the draft FILE it writes (we don't parse its prose).
// opts: { agentMdPath, task, repoDir, pluginDir, draftPath, model, timeoutMs, usePlugin }
export function runAgent(opts) {
  const { agentMdPath, task, repoDir, pluginDir, draftPath, model = "sonnet", timeoutMs = 900_000, usePlugin = true } = opts;
  const system = agentBody(agentMdPath);
  const args = [
    "-p", task,
    "--append-system-prompt", system,
    "--add-dir", repoDir,
    "--dangerously-skip-permissions",
    "--model", model,
    "--output-format", "json"
  ];
  if (usePlugin) args.push("--plugin-dir", pluginDir);

  const t0 = Date.now();
  const proc = spawnSync("claude", args, {
    cwd: repoDir,                 // CLAUDE_PROJECT_DIR = target, like a real run
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env }
  });
  const elapsedMs = Date.now() - t0;
  const meta = parseResult(proc.stdout ?? "");
  return {
    ok: !proc.error && proc.status === 0 && existsSync(draftPath),
    draftWritten: existsSync(draftPath),
    cost: meta.cost,
    turns: meta.turns,
    elapsedMs,
    status: proc.status,
    timedOut: Boolean(proc.error && proc.error.code === "ETIMEDOUT"),
    stderr: (proc.stderr ?? "").slice(-1500),
    agentResult: meta.result.slice(0, 800)
  };
}

// Task prompt for the deep-scanner forked agent. It is told where the prep is, the
// repo root, the plugin path (for callers.mjs), and where to write — and explicitly
// to stay blind (no answer/expected files; there are none under the repo anyway).
export function deepScanTask({ prepPath, repoDir, pluginDir, draftPath }) {
  return [
    `You are running as the deep-scanner (your system prompt has your full instructions).`,
    `Prep file (JSON, lists risk-ranked \`files\` relative to the repo root): ${prepPath}`,
    `Repo root to analyze: ${repoDir}`,
    `FIRST work each file's \`obligations\` list (memory-sink sites): for each, use`,
    `tree_sitter:node_at(file,line) to pull the ENCLOSING FUNCTION (not the whole file),`,
    `trace operands with LSP find-references/go-to-definition, and use the concolic:*`,
    `solver to settle numeric bounds ("can this count exceed the buffer?"). Prove the`,
    `invariant or emit a finding. THEN read each file for other bug classes.`,
    `For cross-file reachability you may also run:`,
    `  node ${pluginDir}/scripts/cmd/callers.mjs --target ${repoDir} --symbol <fn>`,
    `and you have the tree_sitter:* MCP tools for spans/refs.`,
    `Write your findings as JSON of the exact shape { "candidates": [ ... ] } to:`,
    `  ${draftPath}`,
    `Each "finding" candidate MUST include: verdict:"finding", cwe, severity, title,`,
    `rationale (>=150 chars), evidenceAnchors:[{filePath,startLine}], and selfCheck`,
    `(>=40 chars: the guard/invariant that would make it safe, confirmed absent in the`,
    `code). Run your bug-class checklist (esp. use-after-free / GC-rooting / integer`,
    `overflow / stack overflow) on every file, not just injection.`,
    `Then stop. Do not search for or read any "expected", "answer", or CVE-ground-truth`,
    `files — judge the code on its merits only.`
  ].join("\n");
}

// Task prompt for the deep-hunter forked agent — the interprocedural hypothesis loop.
// It gets the ranked anchors + the forward/backward walk CLIs and is told to produce a
// CONFIRMED CROSS-FILE path per finding (the gate the finalizer enforces). Stays blind.
export function deepHuntTask({ prepPath, repoDir, pluginDir, draftPath }) {
  return [
    `You are running as the deep-hunter (your system prompt has your full instructions).`,
    `Prep file (JSON): ${prepPath} — it lists ranked \`anchors\` ({kind, filePath, line,`,
    `signal, enclosingFunction}), a \`budget\` (maxAnchors/maxHops/rounds), and`,
    `\`reachability\` (the walk CLIs). Anchor kinds: "finding" = an existing lead (walk`,
    `from it to find the full flow), "file" = a risk-ranked file with no token match`,
    `(READ THE WHOLE FILE to locate the source/sink — this catches tokenless bugs like`,
    `prototype pollution / logic / broken-tenant — then walk), "source"/"sink" = entry`,
    `/dangerous-op start points.`,
    `Repo root to analyze: ${repoDir}. Plugin scripts at: ${pluginDir}.`,
    `For each anchor run the hypothesis loop: read the enclosing function, hypothesize a`,
    `source→sink flow, and WALK it across files — reading each hop to confirm the tainted`,
    `value actually propagates — using:`,
    `  node ${pluginDir}/scripts/cmd/callees.mjs --target ${repoDir} --file <f> --line <n>   (forward)`,
    `  node ${pluginDir}/scripts/cmd/callers.mjs --target ${repoDir} --symbol <fn>           (backward)`,
    `Attempt every guard on the path; self-falsify before emitting.`,
    `Write JSON { "candidates": [ ... ] } to: ${draftPath}.`,
    `Each "finding" MUST include: verdict:"finding", cwe, severity, title, evidenceLevel,`,
    `source:{filePath,startLine}, sink:{filePath,startLine}, a path:[{filePath,startLine,role}]`,
    `with >=2 hops spanning >=2 files, rationale (>=150 chars), and selfCheck (>=40 chars).`,
    `Use "candidate" when you cannot confirm a cross-file path. Then stop. Do not read any`,
    `"expected", "answer", or CVE-ground-truth files — judge the code on its merits only.`
  ].join("\n");
}

// Task prompt for the fuzz-discoverer forked agent — the discovery-by-execution loop.
// It gets the recon prep (programKind + sanitizer build + dispatch vocabulary), the repo,
// and the draft path, and is told to BUILD THE WHOLE TARGET under sanitizers and DRIVE its
// REAL entry point — NOT retreat to a standalone leaf. It stays blind. The eval finalize
// re-runs the draft locally and the sanitizer report (gated to first-party, non-weak-tier
// crashes) decides truth.
export function fuzzDiscoverTask({ prepPath, repoDir, pluginDir, draftPath }) {
  return [
    `You are running as the fuzz-discoverer (your system prompt has your full instructions).`,
    `Recon prep (JSON): ${prepPath} — read it. It gives \`programKind\` (daemon/cli/library),`,
    `\`harnessStrategy\` (how to drive this target), \`sanitizerBuild.command\` (the project's OWN`,
    `sanitizer build), and \`vocabulary\` ([{name,handlerSymbol,defFilePath}] — the command/method`,
    `grammar). Also \`oracleTargets\` (non-crash classes), \`subsystems\`/\`toolchain\`/\`sanitizeCflags\`.`,
    `If \`oracleTargets\` is non-empty (e.g. a JS package → prototype-pollution), emit an ORACLE`,
    `discovery instead: { oracle, targetModule, inputShape, evidence } — NO harness code, NO build;`,
    `the framework oracle drives standard payloads and checks the invariant (ungameable).`,
    `Repo root to build + run in: ${repoDir}. Plugin scripts at: ${pluginDir}.`,
    ``,
    `BUILD THE WHOLE PROJECT ONCE with \`sanitizerBuild.command\` — fix build snags rather than`,
    `dodging them. Then DRIVE ITS REAL ENTRY POINT per \`harnessStrategy\`:`,
    ` - daemon: run the instrumented binary, connect to its protocol socket, and send SEQUENCES`,
    `   of commands from \`vocabulary\` — seed state with 1-3 setup ops, then a crafted one with`,
    `   boundary/over-limit COUNTS and lengths; capture the server's stderr for the sanitizer abort.`,
    ` - cli: run the binary with malformed argv/stdin/input-file values.`,
    ` - library: link a harness calling the exported / \`vocabulary\` handler symbols with bad inputs.`,
    `DO NOT retreat to hand-compiling a standalone vendored leaf parser (a bundled client lib) —`,
    `that was the prior run's mistake and the finalize REJECTS a crash whose frames are all in`,
    `vendored deps / a stub / your harness. The crash must land in the project's OWN source,`,
    `reached through the entry you drove. A bare signed-integer-overflow with no memory-corruption`,
    `consequence is NOT promoted — escalate it to a real OOB-write/UAF.`,
    ``,
    `Validate a crash reproduces 3/3, then minimize. Write JSON { "discoveries": [ ... ] } to:`,
    `${draftPath}. Each discovery MUST include: title, language, evidence:[{filePath,startLine}]`,
    `(the TARGET source location of the bug, not your harness), preconditions:[...], accessLevel,`,
    `harnessFiles:[{name,content}] (the build+driver that reproduces it), and a buildRunCommand`,
    `that builds + drives the real target and ends by emitting the sanitizer report (offline,`,
    `time-boxed). Your CWE claim is advisory — the finalize sets the verdict + CWE. Then stop.`,
    `Do NOT read any "expected"/"answer"/CVE-ground-truth files — find bugs by running the code only.`
  ].join("\n");
}

export function verifyTask({ prepPath, repoDir, pluginDir, draftPath }) {
  return [
    `You are running as the verifier (your system prompt has your full instructions).`,
    `Verify prep (JSON, lists candidate findings with excerpts): ${prepPath}`,
    `Repo root: ${repoDir}. Plugin scripts at: ${pluginDir}.`,
    `For each candidate, reconstruct source→sink, build a concrete trigger + a negative`,
    `PoC, attempt every guard, devil's-advocate the opposite verdict, then assign a`,
    `verdict. Write JSON { "candidates": [ ... ] } to: ${draftPath}. Then stop.`
  ].join("\n");
}
