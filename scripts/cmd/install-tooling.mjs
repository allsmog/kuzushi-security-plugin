#!/usr/bin/env node
// Vendor / install the analysis tooling relevant to a repo's detected languages.
//
//   node install-tooling.mjs --target <repo> [--include-heavy] [--only <tool>] [--json]
//
// - Language-gated: only tools whose languages intersect the repo's detected
//   languages (unless --only names one explicitly).
// - Light tools (rust-analyzer/clangd/jdtls + native gopls/gtags/semgrep + npm
//   codegraph) install by default; heavy ones (codeql ~1GB, joern ~2GB) only
//   with --include-heavy or --only.
// - Idempotent: already-installed tools are skipped. Writes vendor/.install-state.json.
// - Best-effort + non-fatal: a failure on one tool doesn't abort the rest.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, chmodSync, statSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult, storeFor, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { commandInstalled } from "../lib/capabilities.mjs";
import { VENDOR_TOOLS, downloadUrl, nativeInstallCommand, platformKey } from "../lib/vendor-manifest.mjs";
import { networkInstallAllowed } from "../lib/policy.mjs";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VENDOR_DIR = join(PLUGIN_ROOT, "vendor");
const VENDOR_BIN = join(VENDOR_DIR, "bin");
const CACHE_DIR = join(VENDOR_DIR, ".cache");
const STATE_PATH = join(VENDOR_DIR, ".install-state.json");

function sh(cmd) {
  const r = spawnSync("sh", ["-c", cmd], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { ok: !r.error && r.status === 0, status: r.status, stdout: r.stdout ?? "", stderr: (r.stderr ?? "").slice(0, 4000) };
}

function fileDigest(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function detectedLanguages(target) {
  const store = storeFor(target);
  if (!existsSync(store.runsDir)) return [];
  let latest = null;
  for (const entry of readdirSync(store.runsDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("host-context-")) continue;
    const ctx = join(store.runsDir, entry.name, "context.json");
    if (!existsSync(ctx)) continue;
    const mtime = statSync(ctx).mtime;
    if (!latest || mtime > latest.mtime) latest = { ctx, mtime };
  }
  const byLanguage = latest ? readJsonIfPresent(latest.ctx)?.inventory?.byLanguage ?? {} : {};
  return Object.entries(byLanguage).filter(([l, c]) => l !== "Other" && Number(c) > 0).map(([l]) => l);
}

function isInstalled(tool, t) {
  if (t.method === "npm") return existsSync(join(PLUGIN_ROOT, "node_modules", ".bin", t.npm.split("/").pop()));
  if (t.method === "native") return commandInstalled(nativeProbe(tool));
  return existsSync(join(VENDOR_BIN, t.bin));
}

function nativeProbe(tool) {
  return { gopls: "gopls", gtags: "gtags", semgrep: "semgrep", clangd: "clangd" }[tool] ?? tool;
}

function ensureDirs() {
  mkdirSync(VENDOR_BIN, { recursive: true });
  mkdirSync(CACHE_DIR, { recursive: true });
}

// Write a thin exec wrapper into vendor/bin that runs a binary nested in vendor/.
function writeExecWrapper(name, targetRelToVendor) {
  const path = join(VENDOR_BIN, name);
  writeFileSync(path, `#!/bin/sh\nexec "${join(VENDOR_DIR, targetRelToVendor)}" "$@"\n`);
  chmodSync(path, 0o755);
}

// Find an executable named `name` somewhere under dir (bounded depth).
function findExec(dir, name, depth = 4) {
  if (depth < 0 || !existsSync(dir)) return null;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isFile() && entry.name === name) return full;
    if (entry.isDirectory()) {
      const hit = findExec(full, name, depth - 1);
      if (hit) return hit;
    }
  }
  return null;
}

function installGz(tool, t) {
  const url = downloadUrl(tool);
  if (!url) return { tool, ok: false, reason: `no prebuilt for ${platformKey()}` };
  const gz = join(CACHE_DIR, `${tool}.gz`);
  const dl = sh(`curl -fsSL "${url}" -o "${gz}"`);
  if (!dl.ok) return { tool, ok: false, reason: `download failed: ${dl.stderr || dl.status}` };
  const archiveDigest = fileDigest(gz);
  const out = join(VENDOR_BIN, t.bin);
  const gun = sh(`gunzip -c "${gz}" > "${out}"`);
  rmSync(gz, { force: true });
  if (!gun.ok) return { tool, ok: false, reason: `gunzip failed: ${gun.stderr}` };
  chmodSync(out, 0o755);
  return { tool, ok: true, method: "github-gz", bin: out, url, archiveDigest, binaryDigest: fileDigest(out) };
}

function resolveClangdUrl(t) {
  if (!t.assetPrefix) return null;
  const api = sh(`curl -fsSL "https://api.github.com/repos/${t.repo}/releases/latest"`);
  let tag = "22.1.0";
  if (api.ok) {
    try { tag = JSON.parse(api.stdout).tag_name ?? tag; } catch {}
  }
  return `https://github.com/${t.repo}/releases/download/${tag}/${t.assetPrefix}-${tag}.zip`;
}

function installZip(tool, t) {
  let url = downloadUrl(tool);
  if (url && typeof url === "object") url = resolveClangdUrl(t); // clangd: versioned
  if (!url) return { tool, ok: false, reason: `no prebuilt for ${platformKey()}` };
  const zip = join(CACHE_DIR, `${tool}.zip`);
  const dl = sh(`curl -fsSL "${url}" -o "${zip}"`);
  if (!dl.ok) return { tool, ok: false, reason: `download failed: ${dl.stderr || dl.status}` };
  const archiveDigest = fileDigest(zip);
  const dest = join(VENDOR_DIR, tool);
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  const ex = sh(`unzip -q -o "${zip}" -d "${dest}"`);
  rmSync(zip, { force: true });
  if (!ex.ok) return { tool, ok: false, reason: `unzip failed: ${ex.stderr}` };
  const exe = findExec(dest, t.bin);
  if (!exe) return { tool, ok: false, reason: `binary "${t.bin}" not found in archive` };
  chmodSync(exe, 0o755);
  writeExecWrapper(t.bin, exe.slice(VENDOR_DIR.length + 1));
  return { tool, ok: true, method: "github-zip", bin: join(VENDOR_BIN, t.bin), needsJava: t.needsJava, url, archiveDigest, binaryDigest: fileDigest(exe) };
}

function installTarball(tool, t) {
  const tgz = join(CACHE_DIR, `${tool}.tar.gz`);
  const dl = sh(`curl -fsSL "${t.url}" -o "${tgz}"`);
  if (!dl.ok) return { tool, ok: false, reason: `download failed: ${dl.stderr || dl.status}` };
  const archiveDigest = fileDigest(tgz);
  const dest = join(VENDOR_DIR, tool);
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  const ex = sh(`tar -xzf "${tgz}" -C "${dest}"`);
  rmSync(tgz, { force: true });
  if (!ex.ok) return { tool, ok: false, reason: `extract failed: ${ex.stderr}` };
  return { tool, ok: true, method: "tarball", dir: dest, needsJava: t.needsJava, url: t.url, archiveDigest };
}

function installNative(tool) {
  const cmd = nativeInstallCommand(tool);
  if (!cmd) return { tool, ok: false, reason: `no native installer for ${platformKey()}` };
  const r = sh(cmd.map((c) => (/\s/.test(c) ? `"${c}"` : c)).join(" "));
  return r.ok
    ? { tool, ok: true, method: "native", command: cmd.join(" ") }
    : { tool, ok: false, reason: `native install failed (${cmd.join(" ")}): ${r.stderr || r.status}` };
}

function installOne(tool, t) {
  if (t.method === "npm") {
    return isInstalled(tool, t)
      ? { tool, ok: true, method: "npm", note: "present in node_modules" }
      : { tool, ok: false, reason: `run 'npm install' in the plugin root (dep: ${t.npm})` };
  }
  if (t.method === "github-gz") return installGz(tool, t);
  if (t.method === "github-zip") return installZip(tool, t);
  if (t.method === "tarball") return installTarball(tool, t);
  if (t.method === "native") return installNative(tool);
  return { tool, ok: false, reason: `unknown method ${t.method}` };
}

export function installTooling({ target, includeHeavy = false, only = null, approved = false } = {}) {
  ensureDirs();
  const resolvedTarget = resolve(target ?? ".");
  const detected = new Set(detectedLanguages(resolvedTarget));
  const state = readJsonIfPresent(STATE_PATH) ?? { installed: {}, autoAttempted: false };

  const installed = [];
  const skipped = [];
  const failed = [];
  const needsConfirm = [];

  const tools = only ? [only] : Object.keys(VENDOR_TOOLS);
  for (const tool of tools) {
    const t = VENDOR_TOOLS[tool];
    if (!t) { failed.push({ tool, ok: false, reason: "unknown tool" }); continue; }

    const relevant = only ? true : t.languages.some((l) => detected.has(l));
    if (!relevant) { skipped.push({ tool, reason: "not relevant to detected languages" }); continue; }

    if (isInstalled(tool, t)) { skipped.push({ tool, reason: "already installed" }); continue; }

    if (t.sizeClass === "heavy" && !includeHeavy && !only) {
      needsConfirm.push({ tool, reason: `heavy (~GB) — run: /install ${tool}` });
      continue;
    }

    if (t.method !== "npm") {
      const installGate = networkInstallAllowed(resolvedTarget, { approved, tool });
      if (!installGate.ok) {
        failed.push({ tool, ok: false, reason: installGate.reason, requiresApproval: Boolean(installGate.requiresApproval) });
        continue;
      }
      if (installGate.requirePinnedDigests && !t.sha256) {
        failed.push({ tool, ok: false, reason: "policy.install.requirePinnedDigests=true but this tool has no pinned SHA256 in vendor-manifest.mjs" });
        continue;
      }
    }

    const result = installOne(tool, t);
    if (result.ok) {
      installed.push(result);
      state.installed[tool] = {
        at: new Date().toISOString(),
        method: result.method,
        url: result.url ?? null,
        archiveDigest: result.archiveDigest ?? null,
        binaryDigest: result.binaryDigest ?? null,
        approved: Boolean(approved)
      };
    } else {
      failed.push(result);
    }
  }

  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
  return {
    ok: failed.length === 0,
    status: "completed",
    target: resolvedTarget,
    platform: platformKey(),
    detected: [...detected],
    installed,
    needsConfirm,
    failed,
    skipped
  };
}

// Mark that the background auto-install has run (called by the hook path).
export function markAutoAttempted() {
  ensureDirs();
  const state = readJsonIfPresent(STATE_PATH) ?? { installed: {} };
  state.autoAttempted = true;
  state.autoAttemptedAt = new Date().toISOString();
  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("install-tooling --target <repo> [--include-heavy] [--only <tool>] [--json]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), {
    boolean: ["include-heavy", "json", "mark-auto", "approved", "help"],
    value: ["target", "only"]
  });
  const result = installTooling({
    target: flags.target ?? process.cwd(),
    includeHeavy: Boolean(flags["include-heavy"]),
    only: flags.only ?? null,
    approved: Boolean(flags.approved)
  });
  if (flags["mark-auto"]) markAutoAttempted();
  emitResult(result);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
