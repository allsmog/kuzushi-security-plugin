#!/usr/bin/env node
// Native gtags MCP server. Wraps GNU `global` and `gtags` binaries.
// If the binaries are missing, every tool returns a structured "missing"
// response so callers can degrade gracefully instead of crashing.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.argv.includes("--help")) {
  console.log("gtags MCP server. Tools: gtags:index, gtags:lookup, gtags:references.");
  process.exit(0);
}

const MAX_BUFFER = 10 * 1024 * 1024;
const INSTALL_HINT = "macOS: brew install global    Debian/Ubuntu: apt install global";

function binaryAvailable(name) {
  const result = spawnSync(name, ["--version"], { encoding: "utf8" });
  return !result.error && (result.status === 0 || result.status === null);
}

function gtagsMissingResponse() {
  return { ok: false, missing: "global", install: INSTALL_HINT };
}

// Walk up from `start` looking for the directory that holds GTAGS + GPATH.
// Returns null if we reach the filesystem root without finding one.
function findGtagsRoot(start) {
  let dir = resolve(start);
  while (dir && dir !== "/" && dir !== ".") {
    if (existsSync(join(dir, "GTAGS")) && existsSync(join(dir, "GPATH"))) return dir;
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function resolveDbRoot(root) {
  if (root) return findGtagsRoot(root) ?? resolve(root);
  return findGtagsRoot(".") ?? process.cwd();
}

// `global -x` and `global -rx` emit lines shaped like:
//   <symbol>  <line>  <file>  <excerpt…>
function parseGlobalLine(line) {
  const parts = line.trim().split(/\s+/);
  return {
    symbol: parts[0],
    line: Number(parts[1]),
    file: parts[2],
    excerpt: parts.slice(3).join(" ")
  };
}

function runGlobalLookup(globalArgs, { dbRoot, limit }) {
  const result = spawnSync("global", globalArgs, {
    cwd: dbRoot,
    encoding: "utf8",
    maxBuffer: MAX_BUFFER
  });
  const refs = (result.stdout ?? "")
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(0, limit)
    .map(parseGlobalLine);
  return { ok: result.status === 0, count: refs.length, references: refs };
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function index({ root }) {
  if (!binaryAvailable("gtags")) return gtagsMissingResponse();

  const target = resolve(root ?? ".");
  if (!existsSync(target)) return { ok: false, reason: `root not found: ${target}` };

  const result = spawnSync("gtags", ["-v"], { cwd: target, encoding: "utf8", maxBuffer: MAX_BUFFER });
  return {
    ok: result.status === 0,
    root: target,
    gpath: existsSync(join(target, "GPATH")),
    gtags: existsSync(join(target, "GTAGS")),
    stdout: (result.stdout ?? "").slice(0, 4000),
    stderr: (result.stderr ?? "").slice(0, 2000)
  };
}

async function lookup({ symbol, root, limit = 50 }) {
  if (!binaryAvailable("global")) return gtagsMissingResponse();
  if (!symbol) return { ok: false, reason: "symbol is required" };

  const dbRoot = resolveDbRoot(root);
  if (!existsSync(join(dbRoot, "GTAGS"))) {
    return { ok: false, reason: `GTAGS database not found under ${dbRoot}; run gtags:index first` };
  }

  return { ...runGlobalLookup(["-x", symbol], { dbRoot, limit }), root: dbRoot, symbol };
}

async function references({ symbol, root, limit = 50 }) {
  if (!binaryAvailable("global")) return gtagsMissingResponse();
  if (!symbol) return { ok: false, reason: "symbol is required" };

  const dbRoot = resolveDbRoot(root);
  return { ...runGlobalLookup(["-rx", symbol], { dbRoot, limit }), root: dbRoot, symbol };
}

// ---------------------------------------------------------------------------
// MCP server wiring
// ---------------------------------------------------------------------------

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-gtags", version: "0.2.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "gtags_index",
    {
      title: "gtags:index",
      description: "Build (or refresh) a GNU global GTAGS database rooted at the given directory.",
      inputSchema: { root: z.string().optional() }
    },
    async (args) => asTextResult(await index(args ?? {}))
  );

  server.registerTool(
    "gtags_lookup",
    {
      title: "gtags:lookup",
      description: "Look up the definitions of a symbol in the GTAGS database.",
      inputSchema: {
        symbol: z.string(),
        root: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await lookup(args ?? {}))
  );

  server.registerTool(
    "gtags_references",
    {
      title: "gtags:references",
      description: "Find references to a symbol in the GTAGS database (global -rx).",
      inputSchema: {
        symbol: z.string(),
        root: z.string().optional(),
        limit: z.number().int().optional()
      }
    },
    async (args) => asTextResult(await references(args ?? {}))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`gtags MCP server failed: ${error.stack ?? error.message}`);
  process.exit(1);
});
