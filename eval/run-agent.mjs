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
  const { agentMdPath, task, repoDir, pluginDir, draftPath, model = "sonnet", timeoutMs = 600_000, usePlugin = true } = opts;
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
    `For EACH file, FIRST discharge every entry in its \`obligations\` list: go to that`,
    `line, read the enclosing function, and either prove the stated invariant holds for`,
    `all attacker-influenced input or emit a finding. THEN read the file in full for`,
    `other bug classes. For cross-file reachability you may run:`,
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
