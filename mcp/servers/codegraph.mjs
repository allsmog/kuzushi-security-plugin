#!/usr/bin/env node
// Optional CodeGraph MCP adapter.
//
// This server does not vendor or reimplement CodeGraph. It delegates to an
// installed `codegraph` CLI when one is available and reports a structured
// degraded state otherwise. Use it for high-level repo navigation; pair it
// with the tree-sitter server for exact AST queries and Joern for explicit
// CPG / dataflow work.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.argv.includes("--help")) {
  console.log("codegraph MCP adapter. Tools: codegraph_health, codegraph_status, codegraph_search, codegraph_files, codegraph_context.");
  process.exit(0);
}

const MAX_STDOUT_BYTES = 200_000;
const MAX_STDERR_BYTES = 8_000;
const DEFAULT_MAX_BUFFER = 20 * 1024 * 1024;

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : (process.argv[index + 1] ?? null);
}

const DEFAULT_TARGET = resolve(argValue("--target") ?? process.cwd());

// ---------------------------------------------------------------------------
// CLI bridge
// ---------------------------------------------------------------------------

function commandAvailable(command) {
  const result = spawnSync(command, ["--version"], { encoding: "utf8" });
  return !result.error && (result.status === 0 || result.status === null);
}

function missingCodegraphPayload(extra = {}) {
  return {
    ok: false,
    missing: "codegraph",
    install: "npm install -g @colbymchenry/codegraph",
    initialize: "codegraph init -i",
    ...extra
  };
}

function runCodegraph(args, options = {}) {
  if (!commandAvailable("codegraph")) return missingCodegraphPayload();

  const cwd = resolve(options.target ?? DEFAULT_TARGET);
  if (!existsSync(cwd)) return { ok: false, reason: `target not found: ${cwd}` };

  const result = spawnSync("codegraph", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER
  });
  return {
    ok: result.status === 0,
    status: result.status,
    target: cwd,
    stdout: (result.stdout ?? "").slice(0, options.stdoutLimit ?? MAX_STDOUT_BYTES),
    stderr: (result.stderr ?? "").slice(0, options.stderrLimit ?? MAX_STDERR_BYTES)
  };
}

function parseJsonMaybe(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function health({ target } = {}) {
  if (!commandAvailable("codegraph")) return missingCodegraphPayload();

  const cwd = resolve(target ?? DEFAULT_TARGET);
  const initialized = existsSync(resolve(cwd, ".codegraph"));
  const version = spawnSync("codegraph", ["--version"], { encoding: "utf8" });

  return {
    ok: true,
    ready: initialized,
    target: cwd,
    initialized,
    version: (version.stdout || version.stderr || "").trim(),
    next: initialized ? null : "Run `codegraph init -i` in the target repository."
  };
}

async function status(args = {}) {
  const result = runCodegraph(["status", args.target ?? DEFAULT_TARGET, "--json"], args);
  const parsed = parseJsonMaybe(result.stdout);
  return parsed ? { ...result, parsed } : result;
}

async function search(args = {}) {
  if (!args.query) return { ok: false, reason: "query is required" };

  const cliArgs = ["query", args.query, "--json"];
  if (args.kind) cliArgs.push("--kind", args.kind);
  if (args.limit) cliArgs.push("--limit", String(args.limit));

  const result = runCodegraph(cliArgs, args);
  const parsed = parseJsonMaybe(result.stdout);
  return parsed ? { ...result, results: parsed } : result;
}

async function files(args = {}) {
  const cliArgs = ["files", "--json"];
  if (args.filter) cliArgs.push("--filter", args.filter);
  if (args.maxDepth) cliArgs.push("--max-depth", String(args.maxDepth));

  const result = runCodegraph(cliArgs, args);
  const parsed = parseJsonMaybe(result.stdout);
  return parsed ? { ...result, files: parsed } : result;
}

async function context(args = {}) {
  if (!args.task) return { ok: false, reason: "task is required" };

  const cliArgs = ["context", args.task, "--format", args.format ?? "markdown"];
  if (args.maxNodes) cliArgs.push("--max-nodes", String(args.maxNodes));

  return runCodegraph(cliArgs, args);
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-codegraph", version: "0.2.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "codegraph_health",
    {
      title: "codegraph:health",
      description: "Report CodeGraph CLI availability and whether the target has .codegraph initialized.",
      inputSchema: { target: z.string().optional() }
    },
    async (args) => asTextResult(await health(args))
  );

  server.registerTool(
    "codegraph_status",
    {
      title: "codegraph:status",
      description: "Run `codegraph status --json` for a target repository.",
      inputSchema: { target: z.string().optional() }
    },
    async (args) => asTextResult(await status(args))
  );

  server.registerTool(
    "codegraph_search",
    {
      title: "codegraph:search",
      description: "Search CodeGraph symbols by name/text.",
      inputSchema: {
        target: z.string().optional(),
        query: z.string(),
        kind: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await search(args))
  );

  server.registerTool(
    "codegraph_files",
    {
      title: "codegraph:files",
      description: "Return CodeGraph's indexed file structure.",
      inputSchema: {
        target: z.string().optional(),
        filter: z.string().optional(),
        maxDepth: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await files(args))
  );

  server.registerTool(
    "codegraph_context",
    {
      title: "codegraph:context",
      description: "Build CodeGraph task context for high-level navigation.",
      inputSchema: {
        target: z.string().optional(),
        task: z.string(),
        format: z.enum(["markdown", "json"]).optional(),
        maxNodes: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await context(args))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`codegraph MCP adapter failed: ${error.message}`);
  process.exit(1);
});
