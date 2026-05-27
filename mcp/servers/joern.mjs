#!/usr/bin/env node
// Native Joern MCP server. Thin shim over the `joern` / `joern-parse` CLIs.
// If the binaries are missing, every tool returns a structured "missing"
// response so callers can degrade gracefully.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { assertQueryAllowed } from "../../scripts/lib/policy.mjs";

if (process.argv.includes("--help")) {
  console.log("joern MCP server. Tools: joern:health, joern:parse, joern:query.");
  process.exit(0);
}

const PARSE_MAX_BUFFER = 100 * 1024 * 1024;
const QUERY_MAX_BUFFER = 50 * 1024 * 1024;
const QUERY_STDOUT_LIMIT = 200_000;
const QUERY_STDERR_LIMIT = 5_000;

function joernAvailable() {
  const result = spawnSync("joern", ["--version"], { encoding: "utf8" });
  return !result.error && (result.status === 0 || result.status === null);
}

function joernMissing() {
  return { ok: false, missing: "joern", install: "https://docs.joern.io/installation/" };
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function health() {
  if (!joernAvailable()) return joernMissing();
  const result = spawnSync("joern", ["--version"], { encoding: "utf8" });
  return { ok: true, version: (result.stdout ?? "").trim() };
}

async function parse({ root, output }) {
  if (!joernAvailable()) return joernMissing();

  const sourceRoot = resolve(root ?? ".");
  const cpgPath = resolve(output ?? "./cpg.bin.zip");
  if (!existsSync(sourceRoot)) return { ok: false, reason: `root not found: ${sourceRoot}` };

  const result = spawnSync("joern-parse", [sourceRoot, "--output", cpgPath], {
    encoding: "utf8",
    maxBuffer: PARSE_MAX_BUFFER
  });
  return {
    ok: result.status === 0,
    status: result.status,
    cpg: cpgPath,
    stdout: (result.stdout ?? "").slice(0, 4000),
    stderr: (result.stderr ?? "").slice(0, 2000)
  };
}

async function query({ cpg, script }) {
  if (!joernAvailable()) return joernMissing();
  if (!cpg || !script) return { ok: false, reason: "cpg and script are required" };

  // Tool-boundary policy: confine the CPG path, cap the inline script size, and
  // honor the raw-query posture before executing the script.
  const gate = assertQueryAllowed({ queryPath: cpg, inlineScript: script, fromPath: cpg });
  if (!gate.ok) return gate;

  const result = spawnSync("joern", ["--script", "-", `-Dpath=${cpg}`], {
    input: script,
    encoding: "utf8",
    maxBuffer: QUERY_MAX_BUFFER,
    env: { ...process.env, KUZUSHI_CPG: cpg }
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: (result.stdout ?? "").slice(0, QUERY_STDOUT_LIMIT),
    stderr: (result.stderr ?? "").slice(0, QUERY_STDERR_LIMIT)
  };
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-joern", version: "0.2.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "joern_health",
    { title: "joern:health", description: "Report joern CLI availability." },
    async () => asTextResult(await health())
  );

  server.registerTool(
    "joern_parse",
    {
      title: "joern:parse",
      description: "Parse a source tree into a Joern CPG. Requires the joern CLI.",
      inputSchema: { root: z.string(), output: z.string().optional() }
    },
    async (args) => asTextResult(await parse(args ?? {}))
  );

  server.registerTool(
    "joern_query",
    {
      title: "joern:query",
      description: "Run a Joern script against a parsed CPG. Returns Joern's stdout.",
      inputSchema: { cpg: z.string(), script: z.string() }
    },
    async (args) => asTextResult(await query(args ?? {}))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`joern MCP server failed: ${error.message}`);
  process.exit(1);
});
