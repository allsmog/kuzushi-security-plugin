// Read-only mitigation posture for /mem-exploitability.
//
// Memory-corruption exploitability hinges on which hardening is in play: NX/DEP,
// PIE/ASLR, stack canaries, RELRO, FORTIFY_SOURCE, and Control Flow Guard. We read
// that posture two ways, both read-only:
//
//   detectSourceHardening(target)  — grep the build files (Makefile/CMake/gradle/
//                                     Cargo.toml/*.pro) for the hardening flags.
//   detectBinaryMitigations(path)  — inspect a built artifact: prefer `checksec`,
//                                     else `readelf -a` (ELF), else `otool` (Mach-O).
//
// Nothing here executes the target. `detectBinaryMitigations` only runs read-only
// inspectors against an already-built file, and degrades to nulls when no inspector
// is available. This module never builds, never runs, never weaponizes.

import { closeSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, basename } from "node:path";
import { spawnSync } from "node:child_process";

// Build files we grep for hardening flags, by basename or extension.
const BUILD_FILE_NAMES = new Set([
  "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "Cargo.toml",
  "configure.ac", "configure", "meson.build", "BUILD", "BUILD.bazel"
]);
const BUILD_FILE_EXTS = [".gradle", ".pro", ".cmake", ".mk", ".bazel", ".bzl"];
const SKIP_DIRS = new Set([".git", ".kuzushi", "node_modules", "vendor", "build", "dist", "target", ".joern"]);

function isBuildFile(name) {
  if (BUILD_FILE_NAMES.has(name)) return true;
  return BUILD_FILE_EXTS.some((ext) => name.endsWith(ext));
}

// Bounded recursive walk collecting build files and (separately) candidate
// compiled binaries. Caps directory descent so a huge tree can't hang us.
function walk(root, { maxFiles = 4000, maxDepth = 8 } = {}) {
  const buildFiles = [];
  const binaries = [];
  let seen = 0;
  const stack = [{ dir: root, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop();
    if (depth > maxDepth || seen > maxFiles) break;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (seen > maxFiles) break;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        seen += 1;
        if (isBuildFile(entry.name)) buildFiles.push(full);
        else if (looksLikeBinary(full)) binaries.push(full);
      }
    }
  }
  return { buildFiles, binaries };
}

// Sniff the first bytes for an ELF (\x7fELF) or Mach-O magic. Cheap and avoids
// shelling out to `file`. Only files with an executable-ish size are considered.
function looksLikeBinary(path) {
  let st;
  try { st = statSync(path); } catch { return false; }
  if (st.size < 1024) return false;
  let fd;
  try {
    fd = openSync(path, "r");
    const m = Buffer.alloc(4);
    if (readSync(fd, m, 0, 4, 0) < 4) return false;
    if (m[0] === 0x7f && m[1] === 0x45 && m[2] === 0x4c && m[3] === 0x46) return true; // ELF
    const be = m.readUInt32BE(0);
    const le = m.readUInt32LE(0);
    const machO = [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe];
    return machO.includes(be) || machO.includes(le);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* ignore */ } }
  }
}

// Grep build files for hardening flags. Returns presence booleans + the files
// that evidenced each, so the agent can cite where a flag is (or isn't) set.
export function detectSourceHardening(target) {
  const root = resolve(target);
  const { buildFiles } = walk(root);
  const flags = {
    stackProtector: false, // -fstack-protector* / /GS
    pie: false,            // -fPIE / -pie
    relro: false,          // -z relro / -z now
    fortify: false,        // -D_FORTIFY_SOURCE
    cfg: false,            // /guard:cf
    noExecStack: false     // -z noexecstack
  };
  const evidence = [];
  for (const file of buildFiles) {
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    const rel = relative(root, file);
    const hits = [];
    if (/-fstack-protector|[/\\]GS\b/.test(text)) { flags.stackProtector = true; hits.push("stackProtector"); }
    if (/-fPIE\b|-fpie\b|-pie\b/.test(text)) { flags.pie = true; hits.push("pie"); }
    if (/-z\s+relro|-z\s+now|-Wl,-z,relro|-Wl,-z,now/.test(text)) { flags.relro = true; hits.push("relro"); }
    if (/-D_FORTIFY_SOURCE/.test(text)) { flags.fortify = true; hits.push("fortify"); }
    if (/[/\\]guard:cf\b/.test(text)) { flags.cfg = true; hits.push("cfg"); }
    if (/-z\s+noexecstack|-Wl,-z,noexecstack/.test(text)) { flags.noExecStack = true; hits.push("noExecStack"); }
    if (hits.length) evidence.push({ file: rel, flags: hits });
  }
  return { flags, evidence, buildFilesScanned: buildFiles.length };
}

// Find compiled ELF/Mach-O artifacts under the target (bounded). Returns paths
// relative to the target for reporting; the absolute path is on `.absPath`.
export function findBuiltBinaries(target, limit = 12) {
  const root = resolve(target);
  const { binaries } = walk(root);
  return binaries.slice(0, limit).map((p) => ({ path: relative(root, p), absPath: p, name: basename(p) }));
}

function which(cmd) {
  const r = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], { encoding: "utf8" });
  return r.status === 0 && r.stdout.trim() ? r.stdout.trim().split(/\r?\n/)[0] : null;
}

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 15000, maxBuffer: 16 * 1024 * 1024 });
  if (r.error) return null;
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// checksec --output=json --file=<path> → normalized posture.
function viaChecksec(path) {
  const r = run("checksec", ["--output=json", `--file=${path}`]);
  if (!r || !r.stdout.trim()) return null;
  let parsed;
  try { parsed = JSON.parse(r.stdout); } catch { return null; }
  const entry = parsed[path] ?? Object.values(parsed)[0];
  if (!entry) return null;
  const yes = (v) => typeof v === "string" ? /enabled|yes|full|partial/i.test(v) : Boolean(v);
  return {
    tool: "checksec",
    nx: yes(entry.nx),
    pie: yes(entry.pie),
    canary: yes(entry.canary),
    relro: typeof entry.relro === "string" ? entry.relro.toLowerCase() : (yes(entry.relro) ? "full" : "none"),
    fortify: yes(entry.fortify ?? entry.fortify_source),
    cfg: null
  };
}

// readelf -a parsing (ELF on Linux). Heuristic but standard.
function viaReadelf(path) {
  const r = run("readelf", ["-a", path]);
  if (!r || !r.stdout) return null;
  const out = r.stdout;
  const hasGnuStack = /GNU_STACK/.test(out);
  const stackRwx = /GNU_STACK[^\n]*RWE/.test(out);
  const relroSeg = /GNU_RELRO/.test(out);
  const bindNow = /BIND_NOW|\bNOW\b/.test(out);
  return {
    tool: "readelf",
    nx: hasGnuStack ? !stackRwx : null,
    pie: /Type:\s+DYN/.test(out),
    canary: /__stack_chk_fail|__stack_chk_guard/.test(out),
    relro: relroSeg ? (bindNow ? "full" : "partial") : "none",
    fortify: /_chk@|__memcpy_chk|__sprintf_chk|__strcpy_chk/.test(out),
    cfg: null
  };
}

// otool inspection (Mach-O on macOS). Mach-O is NX + (usually) PIE by default;
// we read the flags from the header and look for the stack-check symbol.
function viaOtool(path) {
  const header = run("otool", ["-hv", path]);
  if (!header || !header.stdout) return null;
  const flags = header.stdout;
  const symbols = run("otool", ["-Iv", path]);
  const symText = symbols?.stdout ?? "";
  return {
    tool: "otool",
    nx: !/ALLOW_STACK_EXECUTION/.test(flags), // absent ⇒ stack non-exec (default)
    pie: /\bPIE\b/.test(flags),
    canary: /___stack_chk_fail|___stack_chk_guard/.test(symText),
    relro: null, // not an ELF concept
    fortify: /_chk\b/.test(symText),
    cfg: null
  };
}

// Inspect one built binary, read-only, best tool available. Returns nulls (never
// throws) when no inspector is on PATH so the caller degrades gracefully.
export function detectBinaryMitigations(path) {
  if (!path || !existsSync(path)) return null;
  let posture = null;
  if (which("checksec")) posture = viaChecksec(path);
  if (!posture && which("readelf")) posture = viaReadelf(path);
  if (!posture && which("otool")) posture = viaOtool(path);
  if (!posture) {
    return { path, tool: null, available: false, nx: null, pie: null, canary: null, relro: null, fortify: null, cfg: null };
  }
  return { path, available: true, ...posture };
}

// Combine source-flag posture with a representative built binary's posture into
// one mitigations block for the prep. binarySelector lets the caller pick (or we
// take the first found). Source signals fill gaps the binary can't show (e.g. no
// binary built yet ⇒ rely on flags).
export function mitigationPosture(target, { binaries } = {}) {
  const source = detectSourceHardening(target);
  const found = binaries ?? findBuiltBinaries(target);
  let binary = null;
  for (const b of found) {
    const m = detectBinaryMitigations(b.absPath ?? resolve(target, b.path));
    if (m && m.available) { binary = { ...m, path: b.path }; break; }
    if (m && !binary) binary = { ...m, path: b.path }; // remember an unavailable one as a fallback
  }
  // Effective posture: prefer binary evidence, fall back to source flags.
  const f = source.flags;
  const effective = {
    nx: binary?.nx ?? (f.noExecStack ? true : null),
    pie: binary?.pie ?? (f.pie ? true : null),
    canary: binary?.canary ?? (f.stackProtector ? true : null),
    relro: binary?.relro ?? (f.relro ? "partial" : null),
    fortify: binary?.fortify ?? (f.fortify ? true : null),
    cfg: binary?.cfg ?? (f.cfg ? true : null)
  };
  return {
    effective,
    source,
    binary,
    binariesFound: found.map((b) => b.path),
    inspector: binary?.tool ?? null,
    platform: process.platform
  };
}
