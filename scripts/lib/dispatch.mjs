// General dispatch / handler entry-point enumeration + program-kind classification.
//
// WHY this exists: command tables, vtables, interpreter registries (luaL_Reg /
// PyMethodDef), and registration calls bind a *name* to a *handler function* with NO
// direct call edge. So a call-graph reachability ranker scores the real attacker entry
// point ~0 and buries it under keyword-matched code (our eval: the discovery lane routed
// to a vendored RESP parser and never the real Redis command handlers, which live in a
// dispatch table generated into commands.def). This library recovers those entry points
// by their STRUCTURAL shape — a string key paired with a function symbol, or a function
// passed to a register-like call — general across dispatch-table systems (interpreters,
// servers, drivers, CLIs), NOT project-specific strings. It (a) resolves each handler to
// the file where it is DEFINED (where the bug lives, e.g. t_stream.c — not the table),
// (b) yields the dispatch *vocabulary* the execution lane drives the real protocol with,
// and (c) classifies program KIND so the lane drives the real entry (socket/argv/API)
// instead of retreating to a leaf. Ripgrep-backed, deterministic; a high-recall HINT.

import { resolve, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { runRg, parseJsonMatches, buildGlobs } from "./ripgrep.mjs";

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// A bare identifier ending in a handler-ish suffix is almost always a registered handler
// even when we can't resolve its definition. General convention across ecosystems.
const HANDLER_NAME = /^[A-Za-z_]\w*(?:Command|Handler|Cmd|Callback|Cb|Proc|Fn|Func|Op|Hook|Action|Dispatch|Exec)$/;
// STRICTER convention for the definition-side scan: a *defined* function whose own name
// matches this is almost certainly an attacker-reachable handler even when its dispatch
// table is generated at build time (e.g. Redis `xackdelCommand` in t_stream.c — the table
// `commands.def` doesn't exist at the pinned commit). General across ecosystems.
const HANDLER_DEF_NAME = /^(?:[a-z]\w*(?:Command|Handler)|on_[a-z]\w+|handle_[a-z]\w+|cmd_[a-z]\w+|[a-z]\w*_(?:handler|cmd|command|callback))$/;
// Derive the dispatch token (command/method name) from a handler symbol, so the execution
// lane gets a real protocol vocabulary: xackdelCommand→xackdel, handle_login→login.
function commandNameFromSymbol(sym) {
  return String(sym)
    .replace(/(?:Command|Handler|Cmd|Callback)$/, "")
    .replace(/^(?:on_|handle_|cmd_)/, "")
    .replace(/_(?:handler|cmd|command|callback)$/, "")
    .toLowerCase();
}
const KEYWORDS = new Set(["if", "for", "while", "switch", "return", "sizeof", "case", "do", "else", "struct", "union", "enum", "const", "static", "void", "int", "char", "long", "short", "unsigned", "signed", "float", "double", "NULL", "null", "true", "false", "nullptr", "typedef", "extern", "inline"]);

// Extra globs: dispatch tables are frequently generated into .def/.inc files (e.g. a
// command table) that the default source globs skip.
const TABLE_GLOBS = ["-g", "*.def", "-g", "*.inc", "-g", "*.tbl", "-g", "*.x"];

// --- function-definition index (so we can VALIDATE a handler symbol is a real function
// and resolve it to the file where it's DEFINED, which is where the bug lives) ----------
const DEF_RE = [
  "^[A-Za-z_][\\w\\s\\*]*?\\b[A-Za-z_]\\w*\\s*\\(",  // C/C++/ObjC/Rust:  rettype name(
  "\\bfunction\\s+[A-Za-z_]\\w*",                      // JS/TS
  "\\bdef\\s+[A-Za-z_]\\w*",                           // Python/Ruby
  "\\bfunc\\s+[A-Za-z_]\\w*",                          // Go
  "\\bfn\\s+[A-Za-z_]\\w*"                             // Rust
].join("|");

function defName(text) {
  const line = String(text ?? "");
  let m = /\b(?:function|def|func|fn)\s+([A-Za-z_]\w*)/.exec(line);
  if (m) return m[1];
  if (/;\s*$/.test(line)) return null;            // C prototype, not a definition
  m = /\b([A-Za-z_]\w*)\s*\(/.exec(line);          // C: identifier right before first '('
  return m ? m[1] : null;
}

// name -> { file, line }. Prefer a non-header definition (real body over a prototype).
function collectDefs(target, scopeDir) {
  const map = new Map();
  const r = runRg(target, ["--json", "-n", "-e", DEF_RE, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return map;
  for (const h of parseJsonMatches(r.stdout, 120000)) {
    const name = defName(h.text);
    if (!name || KEYWORDS.has(name)) continue;
    const file = norm(h.filePath);
    const prev = map.get(name);
    const isHeader = /\.(h|hpp|hh|pyi|d\.ts)$/.test(file);
    if (!prev || (prev.isHeader && !isHeader)) map.set(name, { file, line: h.line ?? 1, isHeader });
  }
  return map;
}

// Candidate dispatch lines (broad rg; precise extraction per-line in JS — rg's Rust
// regex has no lookaround, JS does).
const DISPATCH_RG = [
  "\\{\\s*[\"'][^\"']*[\"']\\s*,",                       // table row:  { "name", fn ...
  "\\b[A-Z][A-Z0-9_]{2,}\\s*\\(\\s*[\"']",               // macro row:  MAKE_CMD("name", ..., fn, ...)
  "\\b\\w*(?:[Rr]egister|[Ss]ubscribe|add_?(?:command|method|handler|route|listener)|define_?method|set_?(?:handler|callback))\\w*\\s*\\("  // register(...)
].join("|");

// Pull (name, handlerSymbol) out of one candidate line. `defs` validates that a symbol
// is a real function (kills data-table false positives like { "string", OBJ_ENCODING }).
function parseDispatchLine(text, defs) {
  const line = String(text ?? "");
  const nameM = /["']([^"']{1,64})["']/.exec(line);
  const name = nameM ? nameM[1] : null;

  // bare identifiers NOT followed by '(' (i.e. references, not calls) and not member-accessed.
  const ids = [];
  const idRe = /(?:^|[^\w.>:&])&?\s*([A-Za-z_]\w*)\b/g;
  let m;
  while ((m = idRe.exec(line)) !== null) {
    const id = m[1];
    const after = line.slice(m.index + m[0].length);
    if (/^\s*\(/.test(after)) continue;                 // it's a call, skip
    if (KEYWORDS.has(id) || /^[A-Z][A-Z0-9_]{2,}$/.test(id)) continue; // keyword / ALL_CAPS const
    ids.push(id);
  }
  if (!ids.length) return null;

  // Accept a symbol only if it's a defined function OR matches the handler convention.
  const ok = (id) => defs.has(id) || HANDLER_NAME.test(id);
  // Prefer a convention-named handler; else the symbol adjacent to the name string.
  let handlerSymbol = ids.filter((id) => HANDLER_NAME.test(id)).pop() || null;
  if (!handlerSymbol) {
    const adj = /[{,(]\s*["'][^"']*["']\s*,\s*&?\s*([A-Za-z_]\w*)\b/.exec(line);
    if (adj && ok(adj[1])) handlerSymbol = adj[1];
  }
  if (!handlerSymbol || !ok(handlerSymbol)) return null;
  const kind = /\{\s*["']/.test(line) ? "pointer-table"
    : /\b[A-Z][A-Z0-9_]{2,}\s*\(/.test(line) ? "macro-table"
    : "registration-call";
  return { name, handlerSymbol, kind };
}

// Enumerate dispatch-registered handlers. Each entry resolves to BOTH the registration
// site (filePath) and the handler's definition site (defFilePath — where the bug lives).
export function enumerateDispatch(target, { scopeDir = ".", cap = 400 } = {}) {
  const resolvedTarget = resolve(target);
  const defs = collectDefs(resolvedTarget, scopeDir);
  const out = [];
  const seen = new Set();
  const push = (e) => { const k = `${e.defFilePath}:${e.handlerSymbol}`; if (!seen.has(k)) { seen.add(k); out.push(e); } };

  // (1) Convention-named handler DEFINITIONS — catches handlers whose dispatch table is
  // generated/absent at source level (Redis commands), straight from where they're defined.
  for (const [name, def] of defs) {
    if (!HANDLER_DEF_NAME.test(name)) continue;
    push({ kind: "convention-def", name: commandNameFromSymbol(name), handlerSymbol: name,
      filePath: def.file, line: def.line, defFilePath: def.file, defLine: def.line, signal: `def ${name}` });
    if (out.length >= cap) break;
  }

  // (2) In-source dispatch tables / registration calls — catches table-registered handlers
  // regardless of naming (e.g. a luaL_Reg row { "get", luaB_get }).
  const r = runRg(resolvedTarget, ["--json", "-n", "--max-count", "500", "-e", DISPATCH_RG, ...buildGlobs(), ...TABLE_GLOBS, scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return out.slice(0, cap);
  for (const h of parseJsonMatches(r.stdout, 12000)) {
    if (out.length >= cap) break;
    const parsed = parseDispatchLine(h.text ?? "", defs);
    if (!parsed) continue;
    const filePath = norm(h.filePath);
    const def = defs.get(parsed.handlerSymbol);
    push({
      ...parsed, filePath, line: h.line ?? 1,
      defFilePath: def?.file ?? filePath, defLine: def?.line ?? h.line ?? 1,
      signal: (h.text ?? "").trim().slice(0, 140)
    });
  }
  return out.slice(0, cap);
}

// Files where dispatch handlers are DEFINED (where the bug lives) — a strong ranking
// signal: a command handler is attacker-reachable surface even with zero inbound call
// edges (the exact blind spot of call-count reachability).
export function dispatchHandlerFiles(target, opts = {}) {
  const set = new Set();
  for (const e of enumerateDispatch(target, opts)) set.add(e.defFilePath);
  return set;
}

// The dispatch VOCABULARY — distinct named handlers the execution lane drives the real
// protocol/CLI with (the Redis command names, a SQL keyword set, a CLI's subcommands).
export function dispatchVocabulary(target, { scopeDir = ".", cap = 200 } = {}) {
  const out = [];
  const seen = new Set();
  for (const e of enumerateDispatch(target, { scopeDir, cap: cap * 3 })) {
    if (!e.name || !/^[A-Za-z][\w.\-]*$/.test(e.name) || seen.has(e.name)) continue;
    seen.add(e.name);
    out.push({ name: e.name, handlerSymbol: e.handlerSymbol, defFilePath: e.defFilePath, defLine: e.defLine });
    if (out.length >= cap) break;
  }
  return out;
}

// --- Program-kind classification ------------------------------------------------------
function countRg(target, pattern, scopeDir = ".") {
  const r = runRg(target, ["--count-matches", "--no-filename", "-e", pattern, ...buildGlobs(), scopeDir === "." ? "." : scopeDir]);
  if (!r.ok) return 0;
  let n = 0;
  for (const line of r.stdout.split(/\r?\n/)) { const v = parseInt(line, 10); if (Number.isFinite(v)) n += v; }
  return n;
}

const MAIN_RE = "\\bint\\s+main\\s*\\(|\\bfunc\\s+main\\s*\\(|\\bfn\\s+main\\s*\\(|def\\s+main\\s*\\(|__name__\\s*==\\s*[\"']__main__[\"']|public\\s+static\\s+void\\s+main";
const SOCKET_RE = "\\b(?:listen|accept|epoll_create\\w*|kqueue|WSAStartup)\\s*\\(|net\\.Listen|ServerSocket|tokio::net|asyncio\\.start_server|http\\.ListenAndServe";
// process-entry argv only — NOT app-level c->argv (which is everywhere in a server).
const ARGV_RE = "\\bchar\\s*\\*\\*?\\s*argv\\b|\\bint\\s+argc\\b|\\bos\\.Args\\b|process\\.argv|std::env::args|\\bsys\\.argv\\b|\\bgetopt\\w*\\s*\\(";
// Real web frameworks only (annotations / app.route / framework names) — not a bare .get(.
const WEB_RE = "@(?:Get|Post|Put|Delete|Patch|Request)Mapping|@app\\.route\\b|@router\\.(?:get|post|put|delete)\\b|\\bhttp\\.ListenAndServe\\b|\\b(?:flask|fastapi|express\\(\\)|django|spring\\.web|gin\\.(?:Default|New))\\b";

// Returns { kind, confidence, signals }. kind ∈ daemon|cli|web-service|library|unknown.
export function classifyProgramKind(target, { scopeDir = "." } = {}) {
  const resolvedTarget = resolve(target);
  const web = countRg(resolvedTarget, WEB_RE, scopeDir);
  const main = countRg(resolvedTarget, MAIN_RE, scopeDir);
  const socket = countRg(resolvedTarget, SOCKET_RE, scopeDir);
  const argv = countRg(resolvedTarget, ARGV_RE, scopeDir);
  const signals = { web, main, socket, argv };

  if (web >= 2) return { kind: "web-service", confidence: "high", signals };
  if (main > 0 && socket > 0) return { kind: "daemon", confidence: socket >= 2 ? "high" : "medium", signals };
  if (main > 0 && argv > 0) return { kind: "cli", confidence: "medium", signals };
  if (main === 0) return { kind: "library", confidence: "medium", signals };
  return { kind: "unknown", confidence: "low", signals };
}

const HARNESS_STRATEGY = {
  daemon: "Build the WHOLE project with sanitizers (use the detected sanitizer build), RUN the instrumented binary, and drive its real input entry (its socket/protocol) with structured command/request sequences built from the dispatch vocabulary — seed prior state with a few setup operations before the crafted one.",
  cli: "Build the WHOLE project with sanitizers, RUN the instrumented binary, and fuzz its real input entry — argv flags, stdin, and any input-file argument — with malformed values.",
  library: "Build the project's objects with sanitizers, then LINK a thin harness that calls the exported API / enumerated handler symbols directly with malformed inputs (libFuzzer-style).",
  "web-service": "Out of scope for the native execution lane — drive the HTTP layer instead.",
  unknown: "Build the WHOLE project with sanitizers and drive whatever real entry point it exposes (main/argv/exported API); do NOT retreat to a standalone leaf parser."
};
export function harnessStrategyFor(kind) { return HARNESS_STRATEGY[kind] ?? HARNESS_STRATEGY.unknown; }

// --- Sanitizer build detection (name the project's OWN build so the agent doesn't
// retreat to a standalone leaf because "building the whole thing looks hard") -----------
export function detectSanitizerBuild(target) {
  const resolvedTarget = resolve(target);
  const read = (f) => { try { return readFileSync(join(resolvedTarget, f), "utf8"); } catch { return ""; } };
  // A project's sanitizer switch often lives in a sub-Makefile (e.g. src/Makefile), while
  // the root Makefile is a thin wrapper — scan the common spots before guessing flags.
  const mkRoot = read("Makefile") || read("makefile") || read("GNUmakefile");
  const mkAll = mkRoot + read("src/Makefile") + read("src/makefile");
  if (mkRoot || mkAll.trim()) {
    if (/\bSANITIZER\b/.test(mkAll)) return { command: "make SANITIZER=address -j", source: "Makefile SANITIZER= switch" };
    if (/\bASAN\b/.test(mkAll)) return { command: "make ASAN=1 -j", source: "Makefile ASAN switch" };
    return { command: 'make -j CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"', source: "Makefile (injected sanitizer flags)" };
  }
  if (existsSync(join(resolvedTarget, "CMakeLists.txt"))) {
    return { command: 'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && cmake --build build-asan -j', source: "CMakeLists.txt" };
  }
  if (existsSync(join(resolvedTarget, "configure"))) {
    return { command: 'CFLAGS="-fsanitize=address,undefined -g -O1" LDFLAGS="-fsanitize=address,undefined" ./configure && make -j', source: "autotools ./configure" };
  }
  if (existsSync(join(resolvedTarget, "Cargo.toml"))) {
    return { command: 'RUSTFLAGS="-Zsanitizer=address" cargo +nightly build -Zbuild-std --target x86_64-unknown-linux-gnu', source: "Cargo.toml (nightly -Zsanitizer)" };
  }
  return null;
}
