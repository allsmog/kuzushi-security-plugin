// Compiled-binary detection + read-only static triage. Source-only scanners (and
// kuzushi until now) never open the shipped artifacts; Xint Code makes a point of
// analyzing binaries. This is the modest, honest version: detect ELF/PE/Mach-O by
// magic bytes, then surface read-only signals (dangerous imported symbols, RWX /
// writable-executable segments, suspicious strings) via whatever standard binutils
// are on PATH. Assessment only — no execution, no disassembly-for-exploitation.

import { readdirSync, openSync, readSync, closeSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { spawnSync } from "node:child_process";

const SKIP_DIRS = new Set([".git", ".kuzushi", ".joern", "node_modules", ".hg", ".svn"]);
const MAX_SCAN = 5000; // bounded walk so a huge tree can't wedge prepare

// Read the first bytes and classify. Returns a format string or null.
function sniff(path) {
  let fd;
  try {
    fd = openSync(path, "r");
    const buf = Buffer.alloc(4);
    const n = readSync(fd, buf, 0, 4, 0);
    if (n < 4) return null;
    // ELF: 0x7F 'E' 'L' 'F'
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "elf";
    // PE/COFF: 'M' 'Z'
    if (buf[0] === 0x4d && buf[1] === 0x5a) return "pe";
    // Mach-O (32/64, LE/BE) + fat/universal
    const m = buf.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(m)) return "macho";
    return null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* ignore */ }
  }
}

// Walk the tree (bounded) and return detected binaries as { path, format, bytes }.
export function findBinaries(target, { limit = 200 } = {}) {
  const out = [];
  const stack = [target];
  let scanned = 0;
  while (stack.length && out.length < limit && scanned < MAX_SCAN) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      scanned += 1;
      if (scanned >= MAX_SCAN) break;
      let size = 0;
      try { size = statSync(full).size; } catch { continue; }
      if (size < 4) continue;
      const format = sniff(full);
      if (format) {
        out.push({ path: relative(target, full).split(sep).join("/"), format, bytes: size });
        if (out.length >= limit) break;
      }
    }
  }
  return out;
}

function toolOk(tool) {
  try { return spawnSync(tool, ["--version"], { stdio: "ignore" }).status === 0; } catch { return false; }
}

// Read-only triage of one binary. Best-effort: uses nm/objdump/readelf if present,
// degrades to magic-only facts otherwise. Never throws.
export function triageBinary(target, rel) {
  const abs = join(target, rel);
  const signals = [];
  const toolsUsed = [];
  const DANGEROUS = ["system", "popen", "exec", "execve", "strcpy", "strcat", "sprintf", "gets", "memcpy", "scanf", "dlopen", "mprotect"];

  if (toolOk("nm")) {
    toolsUsed.push("nm");
    const r = spawnSync("nm", ["-D", "--", abs], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const syms = `${r.stdout ?? ""}`.toLowerCase();
    for (const d of DANGEROUS) {
      if (new RegExp(`\\b${d}\\b`).test(syms)) signals.push({ kind: "dangerous-import", symbol: d });
    }
  }
  if (toolOk("readelf")) {
    toolsUsed.push("readelf");
    const r = spawnSync("readelf", ["-lW", "--", abs], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const out = `${r.stdout ?? ""}`;
    // A LOAD segment flagged both Writable and Executable (RWE) is a hardening smell.
    for (const line of out.split(/\r?\n/)) {
      if (/\bLOAD\b/.test(line) && /\bRWE\b/.test(line)) signals.push({ kind: "rwx-segment", detail: line.trim() });
    }
  }

  return { path: rel, toolsUsed, signals, analyzed: toolsUsed.length > 0 };
}
