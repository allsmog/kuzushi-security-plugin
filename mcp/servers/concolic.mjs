#!/usr/bin/env node
// Optional concolic / constraint-solving MCP server. Thin shims over the `z3`
// SMT solver and the `crosshair` Python concolic tool. If a tool's CLI is not
// installed, that tool returns a structured "missing" response (self-gating,
// like codeql/joern) — /path-solve falls back to the LLM solver.
//
// SAFETY: z3 is a pure solver (no target code runs). CrossHair *imports and
// executes the target module*, so it is gated behind an explicit `trustExec`
// flag (mirrors the sandbox `trustLocal` gate) — run it only on code you trust.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.argv.includes("--help")) {
  console.log("concolic MCP server. Tools: concolic:health, concolic:z3_solve, concolic:crosshair.");
  process.exit(0);
}

const SOLVE_MAX_BUFFER = 16 * 1024 * 1024;
const STDOUT_LIMIT = 200_000;
const Z3_INSTALL = "pip install z3-solver  (or: brew install z3 / apt-get install z3)";
const CROSSHAIR_INSTALL = "pip install crosshair-tool";

function toolAvailable(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  return !r.error && (r.status === 0 || r.status === null);
}
const z3Available = () => toolAvailable("z3", ["--version"]);
const crosshairAvailable = () => toolAvailable("crosshair", ["--version"]);

function clip(s, n = STDOUT_LIMIT) {
  return typeof s === "string" && s.length > n ? `${s.slice(0, n)}\n…[truncated]` : (s ?? "");
}

async function health() {
  return {
    ok: true,
    z3: { available: z3Available(), install: Z3_INSTALL },
    crosshair: { available: crosshairAvailable(), install: CROSSHAIR_INSTALL },
    note: "z3 solves SMT-LIB predicates (safe). crosshair executes target Python (pass trustExec:true)."
  };
}

// Solve an SMT-LIB problem. Accept a full `smtlib` program, or assemble one from
// `declarations` + `assertions` (we append (check-sat)(get-model)).
function z3Solve({ smtlib, declarations = [], assertions = [], timeoutMs = 10000 }) {
  if (!z3Available()) return { ok: false, missing: "z3", install: Z3_INSTALL };
  let program = smtlib;
  if (!program) {
    if (!assertions.length) return { ok: false, error: "provide `smtlib` or at least one `assertions` entry" };
    program = [
      ...declarations,
      ...assertions.map((a) => (a.trim().startsWith("(assert") ? a : `(assert ${a})`)),
      "(check-sat)",
      "(get-model)"
    ].join("\n");
  }
  const r = spawnSync("z3", ["-smt2", "-in", `-T:${Math.ceil(timeoutMs / 1000)}`], {
    input: program, encoding: "utf8", maxBuffer: SOLVE_MAX_BUFFER, timeout: timeoutMs + 2000
  });
  if (r.error) return { ok: false, error: String(r.error.message ?? r.error) };
  const out = `${r.stdout ?? ""}`.trim();
  const firstLine = out.split(/\r?\n/)[0]?.trim() ?? "";
  const sat = firstLine === "sat" ? "sat" : firstLine === "unsat" ? "unsat" : "unknown";
  return { ok: true, sat, model: clip(out), program: clip(program, 4000) };
}

// Run `crosshair check <file>` to surface contract counterexamples / inputs that
// reach failures. Gated: executes the target module. Time-boxed.
function crosshair({ file, target, trustExec = false, timeoutMs = 30000, extraArgs = [] }) {
  if (!crosshairAvailable()) return { ok: false, missing: "crosshair", install: CROSSHAIR_INSTALL };
  if (!file) return { ok: false, error: "`file` (a Python file) is required" };
  if (!trustExec) {
    return { ok: false, needsConsent: true, note: "crosshair imports and EXECUTES the target module. Pass trustExec:true to run — only on code you trust (or run it inside a container)." };
  }
  const abs = resolve(file);
  if (!existsSync(abs)) return { ok: false, error: `file not found: ${file}` };
  const targetArg = target ? `${abs}:${target}` : abs;
  const r = spawnSync("crosshair", ["check", targetArg, ...extraArgs], {
    encoding: "utf8", maxBuffer: SOLVE_MAX_BUFFER, timeout: timeoutMs
  });
  if (r.error) return { ok: false, error: String(r.error.message ?? r.error), timedOut: r.error.code === "ETIMEDOUT" };
  return { ok: true, exitCode: r.status, stdout: clip(r.stdout), stderr: clip(r.stderr, 5000) };
}

function asTextResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function main() {
  const server = new McpServer(
    { name: "kuzushi-concolic", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "concolic_health",
    { title: "concolic:health", description: "Report z3 + crosshair availability and install hints." },
    async () => asTextResult(await health())
  );

  server.registerTool(
    "concolic_z3_solve",
    {
      title: "concolic:z3_solve",
      description: "Solve an SMT-LIB problem with z3 (pure solver, no target code runs). Provide `smtlib` or `declarations`+`assertions`; returns sat/unsat + model.",
      inputSchema: {
        smtlib: z.string().optional(),
        declarations: z.array(z.string()).optional(),
        assertions: z.array(z.string()).optional(),
        timeoutMs: z.number().int().positive().optional()
      }
    },
    async (args) => asTextResult(z3Solve(args ?? {}))
  );

  server.registerTool(
    "concolic_crosshair",
    {
      title: "concolic:crosshair",
      description: "Run crosshair on a Python file/function to find a counterexample input. EXECUTES target code — requires trustExec:true.",
      inputSchema: {
        file: z.string(),
        target: z.string().optional(),
        trustExec: z.boolean().optional(),
        timeoutMs: z.number().int().positive().optional(),
        extraArgs: z.array(z.string()).optional()
      }
    },
    async (args) => asTextResult(crosshair(args ?? {}))
  );

  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error(`concolic MCP server failed: ${error.message}`);
  process.exit(1);
});
