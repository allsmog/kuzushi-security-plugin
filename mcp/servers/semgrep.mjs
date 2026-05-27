#!/usr/bin/env node
// Optional Semgrep MCP server. Wraps `semgrep --json`. If the CLI is not
// installed, every tool returns a structured "missing" response.
//
// Hits surface as *evidence*, not findings — the host Claude session decides
// whether to promote them. This is deliberate: rule hits are noisy and
// re-validating them keeps the thesis intact (the model decides, scanners
// provide leads).

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.argv.includes("--help")) {
  console.log("semgrep MCP server. Tools: semgrep_health, semgrep_scan, semgrep_rules.");
  process.exit(0);
}

const INSTALL_URL = "https://semgrep.dev/docs/getting-started/#getting-started";
const SCAN_MAX_BUFFER = 200 * 1024 * 1024;
const STDOUT_LIMIT = 1_000_000;
const STDERR_LIMIT = 5_000;

function semgrepAvailable() {
  const result = spawnSync("semgrep", ["--version"], { encoding: "utf8" });
  return !result.error && result.status === 0;
}

function semgrepMissing() {
  return {
    ok: false,
    missing: "semgrep",
    install: INSTALL_URL,
    note: "Install via `pip install semgrep` or `brew install semgrep`. Optional — kuzushi runs without it; this server only surfaces hits as evidence."
  };
}

function tryParseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function health() {
  if (!semgrepAvailable()) return semgrepMissing();
  const result = spawnSync("semgrep", ["--version"], { encoding: "utf8" });
  return { ok: true, version: (result.stdout ?? "").trim() };
}

async function scan({ target = ".", config = "auto", severity = null, timeout = 60 }) {
  if (!semgrepAvailable()) return semgrepMissing();
  const dir = resolve(target);
  if (!existsSync(dir)) return { ok: false, reason: `target not found: ${dir}` };

  const args = ["--json", "--config", config, "--timeout", String(timeout), "--metrics", "off", dir];
  if (severity) args.push("--severity", severity);

  const result = spawnSync("semgrep", args, {
    encoding: "utf8",
    maxBuffer: SCAN_MAX_BUFFER
  });

  // Semgrep exits 0 on no findings, 1 on findings, 2+ on errors. Both 0 and 1
  // give us a valid JSON document — surface either as ok.
  if (result.status !== 0 && result.status !== 1) {
    return {
      ok: false,
      status: result.status,
      stderr: (result.stderr ?? "").slice(0, STDERR_LIMIT)
    };
  }

  const parsed = tryParseJson(result.stdout);
  if (!parsed) {
    return {
      ok: false,
      reason: "could not parse semgrep --json output",
      raw: (result.stdout ?? "").slice(0, 4000)
    };
  }

  const results = (parsed.results ?? []).map((row) => ({
    ruleId: row.check_id,
    severity: row.extra?.severity ?? "INFO",
    message: row.extra?.message ?? "",
    file: row.path,
    startLine: row.start?.line ?? null,
    endLine: row.end?.line ?? null,
    lines: row.extra?.lines ?? null
  }));

  return {
    ok: true,
    count: results.length,
    results,
    stdoutBytes: result.stdout.length,
    truncatedStdout: result.stdout.length > STDOUT_LIMIT
  };
}

async function rules({ packs = [] }) {
  if (!semgrepAvailable()) return semgrepMissing();
  // Convenience tool: returns the bundled kuzushi rules so the host can
  // inspect what would be applied.
  const repoRoot = resolve(new URL("../../", import.meta.url).pathname);
  const rulesDir = resolve(repoRoot, "rules");
  if (!existsSync(rulesDir)) return { ok: true, packs: [], note: "no rules/ dir bundled" };
  const list = [];
  try {
    const { readdirSync } = await import("node:fs");
    for (const entry of readdirSync(rulesDir)) {
      if (!/\.ya?ml$/i.test(entry)) continue;
      if (packs.length > 0 && !packs.includes(entry)) continue;
      list.push({ name: entry, path: `rules/${entry}` });
    }
  } catch {
    // ignore — return what we have
  }
  return { ok: true, packs: list };
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-semgrep", version: "1.0.0-rc.1" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "semgrep_health",
    { title: "semgrep:health", description: "Report semgrep CLI availability and version." },
    async () => asTextResult(await health())
  );

  server.registerTool(
    "semgrep_scan",
    {
      title: "semgrep:scan",
      description: "Run semgrep against a target directory. Returns parsed results as evidence; the host model decides which to promote to findings.",
      inputSchema: {
        target: z.string().optional(),
        config: z.string().optional(),
        severity: z.enum(["INFO", "WARNING", "ERROR"]).optional(),
        timeout: z.number().int().positive().optional()
      }
    },
    async (args) => asTextResult(await scan(args ?? {}))
  );

  server.registerTool(
    "semgrep_rules",
    {
      title: "semgrep:rules",
      description: "List bundled kuzushi rule packs available under rules/.",
      inputSchema: {
        packs: z.array(z.string()).optional()
      }
    },
    async (args) => asTextResult(await rules(args ?? {}))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`semgrep MCP server failed: ${error.message}`);
  process.exit(1);
});
