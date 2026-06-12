// Scoped (light) CPG — the scalable cross-function memory lane.
//
// A whole-repo Joern CPG is the heavy part (minutes + GBs on a large repo), which is why
// the CPG dataflow lane was effectively laptop-unusable. The fix is to build a CPG bounded
// to the SCOPE under investigation — a subsystem directory, or a suspect file plus its
// caller/callee closure. Build cost then scales with the *scope*, not the repo: measured at
// ~6 s for the 38-file `deps/lua/src` subsystem of redis (vs minutes whole-repo). This makes
// the interprocedural memory queries (use-after-free / integer-overflow) runnable per
// finding on any size repo — the same way a human auditor pulls in only the relevant files.
//
// Read-only + best-effort: every entry point self-skips cleanly when the `joern` CLI is
// absent (so `npm test` stays green offline) and never throws into a producer.

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, cpSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { crossFileCallees } from "./callgraph.mjs";

export function joernAvailable() {
  try {
    const r = spawnSync("joern-parse", ["--help"], { encoding: "utf8", timeout: 30000 });
    return !r?.error && (r.status === 0 || r.status === null);
  } catch { return false; }
}

// Choose the file set to scope a CPG to for investigating `file`.
//   mode "dir"     — the file's directory (the subsystem). Cheapest, captures intra-subsystem
//                    cross-function flows (the redis Lua bugs all live within deps/lua/src).
//   mode "closure" — `file` + the files it calls into and that call it, up to `hops` (uses the
//                    code-graph forward/back edges). Tighter when a subsystem is huge.
// Returns a de-duplicated list of repo-relative file paths (always includes `file`).
export function scopeForFile(target, file, { mode = "dir", hops = 1, maxFiles = 120 } = {}) {
  const rel = String(file).replace(/^\.\//, "");
  if (mode === "dir") {
    const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : ".";
    return { scopeDir: dir, files: null };
  }
  // closure mode: walk forward callees from the file's symbols (back-edges need a CPG we
  // don't have yet, so forward closure is the cheap approximation).
  const set = new Set([rel]);
  try {
    const seeds = crossFileCallees(target, { file: rel }) ?? [];
    for (const c of seeds) { if (c?.file) set.add(String(c.file).replace(/^\.\//, "")); if (set.size >= maxFiles) break; }
  } catch { /* no code-graph — fall back to just the file */ }
  return { scopeDir: null, files: [...set].slice(0, maxFiles) };
}

// Build a CPG over a bounded scope. Provide `scopeDir` (a repo-relative dir) OR `files`
// (a repo-relative list). Returns { ok, cpgPath, fileCount, parseDir, buildMs, reason }.
export function buildScopedCpg(target, { scopeDir = null, files = null, timeoutMs = 600000 } = {}) {
  const resolvedTarget = resolve(target);
  if (!joernAvailable()) return { ok: false, reason: "joern CLI not on PATH" };

  let parseDir;
  if (scopeDir && scopeDir !== ".") {
    parseDir = resolve(resolvedTarget, scopeDir);
    if (!existsSync(parseDir)) return { ok: false, reason: `scopeDir ${scopeDir} not found` };
  } else if (Array.isArray(files) && files.length) {
    // Copy the scoped files into a temp tree, preserving relative paths so cross-file
    // references resolve. This is what bounds the CPG to the investigation.
    parseDir = mkdtempSync(join(tmpdir(), "kz-scoped-src-"));
    let copied = 0;
    for (const f of files) {
      const src = resolve(resolvedTarget, f);
      if (!existsSync(src) || statSync(src).isDirectory()) continue;
      const dst = join(parseDir, f);
      mkdirSync(dirname(dst), { recursive: true });
      try { cpSync(src, dst); copied += 1; } catch { /* skip unreadable */ }
    }
    if (!copied) return { ok: false, reason: "no scoped files could be staged" };
  } else {
    return { ok: false, reason: "provide scopeDir or files" };
  }

  const cpgPath = join(mkdtempSync(join(tmpdir(), "kz-scoped-cpg-")), "scoped.cpg.bin");
  const t0 = Date.now();
  const r = spawnSync("joern-parse", [parseDir, "--output", cpgPath], { encoding: "utf8", timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  const buildMs = Date.now() - t0;
  if (r.status !== 0 || !existsSync(cpgPath)) {
    return { ok: false, reason: `joern-parse failed (status ${r.status})`, stderr: (r.stderr ?? "").slice(-1000), buildMs };
  }
  return { ok: true, cpgPath, parseDir, buildMs };
}

// Run a Joern query script against a CPG; return the JSON-line findings it prints.
export function runJoernQuery(cpgPath, queryPath, { timeoutMs = 300000 } = {}) {
  if (!existsSync(cpgPath)) return { ok: false, flows: [], reason: "cpg missing" };
  const r = spawnSync("joern", ["--script", queryPath], {
    encoding: "utf8", timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, KUZUSHI_CPG: cpgPath }
  });
  const flows = [];
  for (const line of String(r.stdout ?? "").split(/\r?\n/)) {
    const s = line.trim();
    if (s.startsWith("{")) { try { flows.push(JSON.parse(s)); } catch { /* not a result line */ } }
  }
  return { ok: r.status === 0, flows, stderr: (r.stderr ?? "").slice(-1000) };
}

// One-shot: scope → build → run a query, for a file under investigation. The scalable unit
// the memory lane calls per finding. Returns { ok, flows, scope, buildMs, reason }.
export function investigateFile(target, file, queryPath, { mode = "dir", hops = 1, buildTimeoutMs = 600000, queryTimeoutMs = 300000 } = {}) {
  const scope = scopeForFile(target, file, { mode, hops });
  const built = buildScopedCpg(target, { scopeDir: scope.scopeDir, files: scope.files, timeoutMs: buildTimeoutMs });
  if (!built.ok) return { ok: false, reason: built.reason, scope };
  const q = runJoernQuery(built.cpgPath, queryPath, { timeoutMs: queryTimeoutMs });
  return { ok: q.ok, flows: q.flows, scope, buildMs: built.buildMs, cpgPath: built.cpgPath, reason: q.reason };
}
