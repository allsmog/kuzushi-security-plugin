// Capability matrix: map detected languages → relevant LSP servers and MCP
// backends. Keyed off context-build's inventory.byLanguage (the language names
// it emits: Java, Kotlin, Ruby, Python, JavaScript, TypeScript, C, C++, Rust,
// Go, PHP, Scala, Other).
//
// Conditionality:
//  - LSP servers are auto-gated by file extension by Claude Code itself; this
//    matrix is for *reporting* which are relevant + whether the binary is
//    installed (we cannot install language-server binaries).
//  - MCP backends cannot be conditionally started by Claude Code, so this drives
//    the advisory selector (which backends to enable) and the self-gating
//    tree-sitter server's relevance.
//
// Language coverage adapted from kuzushi: the module_recommender language→codeql
// map (adapters.rs) and scripts/lib/mcp.mjs SUPPORTED_BACKENDS.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// A tool counts as "available" if it's been vendored into the plugin (vendor/bin
// or, for jdtls, vendor/jdtls), shipped via npm (node_modules/.bin), or found on
// PATH. `name` is the tool/binary name (jdtls is special-cased to its dir).
export function toolAvailable(name) {
  if (!name) return false;
  if (name === "jdtls" && existsSync(join(PLUGIN_ROOT, "vendor", "jdtls", "plugins"))) return true;
  if (existsSync(join(PLUGIN_ROOT, "vendor", "bin", name))) return true;
  if (existsSync(join(PLUGIN_ROOT, "node_modules", ".bin", name))) return true;
  return commandInstalled(name);
}

export const LSP_SERVERS = [
  { name: "gopls", languages: ["Go"], extensions: [".go"], command: "gopls",
    installHint: "go install golang.org/x/tools/gopls@latest" },
  { name: "jdtls", languages: ["Java"], extensions: [".java"], command: "jdtls",
    installHint: "macOS: brew install jdtls | or download eclipse.jdt.ls" },
  { name: "typescript-language-server", languages: ["JavaScript", "TypeScript"],
    extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"], command: "typescript-language-server",
    bundled: true, installHint: "bundled (plugin node_modules)" },
  { name: "pyright", languages: ["Python"], extensions: [".py"], command: "pyright-langserver",
    bundled: true, installHint: "bundled (plugin node_modules)" },
  { name: "rust-analyzer", languages: ["Rust"], extensions: [".rs"], command: "rust-analyzer",
    installHint: "rustup component add rust-analyzer" },
  { name: "clangd", languages: ["C", "C++"], extensions: [".c", ".cc", ".cpp", ".h", ".hpp"], command: "clangd",
    installHint: "macOS: Xcode CLT | Debian/Ubuntu: apt install clangd" }
];

export const MCP_BACKENDS = [
  // tree-sitter is our own bundled, self-gating Node server — it applies to any
  // repo with source files and is always "installed" (no external binary).
  { name: "tree-sitter", universal: true, bundled: true, selfGating: true,
    languages: ["Java", "Kotlin", "Ruby", "JavaScript", "TypeScript", "Python", "C", "C++", "Rust", "Go", "PHP", "Scala"],
    installHint: "bundled (web-tree-sitter)" },
  { name: "codeql", probe: "codeql",
    languages: ["Go", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Ruby", "C", "C++"],
    installHint: "github.com/github/codeql-cli-binaries/releases" },
  { name: "joern", probe: "joern",
    languages: ["C", "C++", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go"],
    installHint: "docs.joern.io/installation" },
  { name: "clang", probe: "clang", languages: ["C", "C++"],
    installHint: "macOS: Xcode CLT | Debian/Ubuntu: apt install clang" },
  { name: "gtags", probe: "gtags", languages: ["C", "C++", "Java", "JavaScript", "Python", "PHP"],
    installHint: "macOS: brew install global | Debian/Ubuntu: apt install global" },
  { name: "semgrep", probe: "semgrep",
    languages: ["Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "Ruby", "C", "C++", "PHP", "Scala"],
    installHint: "pip install semgrep | brew install semgrep" },
  { name: "codegraph", probe: "codegraph", languages: ["JavaScript", "TypeScript", "Python", "Java", "Go"],
    installHint: "npm install -g @colbymchenry/codegraph" },
  // Optional concolic backend for /path-solve. The kuzushi-concolic server always
  // connects; its solver CLIs are opt-in — z3 (numeric/string, any language) and
  // crosshair (Python source concolic). cliInstalled probes z3 (the general one);
  // crosshair is reported by concolic:health and installed via /install crosshair.
  { name: "concolic", probe: "z3",
    languages: ["Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "Ruby", "C", "C++", "Rust", "PHP", "Scala"],
    installHint: "optional solvers: pip install z3-solver (numeric/string) and/or crosshair-tool (Python)" }
];

// Cheap, cached PATH probe. `which` is reliable across the language servers and
// analysis CLIs (more so than `--version`, which some servers reject).
const probeCache = new Map();
export function commandInstalled(command) {
  if (!command) return false;
  if (probeCache.has(command)) return probeCache.get(command);
  let ok = false;
  try {
    const result = spawnSync("which", [command], { stdio: "ignore" });
    ok = !result.error && result.status === 0;
  } catch {
    ok = false;
  }
  probeCache.set(command, ok);
  return ok;
}

// The named languages actually present in the repo (drops "Other" and zero counts).
export function detectedLanguages(byLanguage) {
  return Object.entries(byLanguage ?? {})
    .filter(([lang, count]) => lang !== "Other" && Number(count) > 0)
    .map(([lang]) => lang);
}

// Select the LSP servers + MCP backends relevant to the detected languages,
// each annotated with whether its binary is installed. Returns only relevant
// entries (callers that want the full matrix can read LSP_SERVERS/MCP_BACKENDS).
export function selectCapabilities(byLanguage) {
  const detected = detectedLanguages(byLanguage);
  const present = new Set(detected);

  const lsp = LSP_SERVERS
    .filter((server) => server.languages.some((lang) => present.has(lang)))
    .map((server) => ({
      name: server.name,
      command: server.command,
      bundled: Boolean(server.bundled),
      languages: server.languages.filter((lang) => present.has(lang)),
      extensions: server.extensions,
      // Bundled servers ship in node_modules; others may be vendored or on PATH.
      installed: server.bundled ? true : toolAvailable(server.name),
      installHint: server.installHint
    }));

  const mcp = MCP_BACKENDS
    .filter((backend) => (backend.universal ? detected.length > 0 : backend.languages.some((lang) => present.has(lang))))
    .map((backend) => ({
      name: backend.name,
      universal: Boolean(backend.universal),
      selfGating: Boolean(backend.selfGating),
      bundled: Boolean(backend.bundled),
      languages: backend.universal ? detected : backend.languages.filter((lang) => present.has(lang)),
      installed: backend.bundled ? true : (toolAvailable(backend.name) || toolAvailable(backend.probe)),
      installHint: backend.installHint
    }));

  return { detected, lsp, mcp };
}
