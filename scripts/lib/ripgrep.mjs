// Ripgrep wrapper used by context-build (and future host scripts) to walk
// source files. Centralizes rg discovery, spawn, and the include/exclude glob
// set.
//
// rg discovery: many users don't have ripgrep on PATH but do have it bundled
// with VS Code, Cursor, Codex, or the @vscode/ripgrep npm package. We probe a
// handful of well-known locations on first use so the plugin works out of the
// box without forcing `brew install ripgrep`. If rg is genuinely unavailable,
// listFiles() falls back to a pure-Node recursive walk so context-build never
// silently produces an empty inventory.

import { existsSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { spawnSync } from "node:child_process";

let resolvedRgPath = null;
function resolveRg() {
  if (resolvedRgPath) return resolvedRgPath;
  if (process.env.KUZUSHI_RG) {
    if (existsSync(process.env.KUZUSHI_RG)) {
      resolvedRgPath = process.env.KUZUSHI_RG;
      return resolvedRgPath;
    }
  }
  const probes = [
    "/opt/homebrew/bin/rg",
    "/usr/local/bin/rg",
    "/usr/bin/rg",
    "/Applications/Codex.app/Contents/Resources/rg",
    "/Applications/Cursor.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg",
    "/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg"
  ];
  for (const candidate of probes) {
    if (existsSync(candidate)) {
      resolvedRgPath = candidate;
      return candidate;
    }
  }
  // Last resort: rely on PATH lookup. spawnSync will surface ENOENT if missing.
  resolvedRgPath = "rg";
  return "rg";
}

export function ripgrepPath() {
  return resolveRg();
}

const DEFAULT_GLOBS = [
  "*.java",
  "*.kt",
  "*.kts",
  "*.scala",
  "*.js",
  "*.jsx",
  "*.ts",
  "*.tsx",
  "*.mjs",
  "*.cjs",
  "*.c",
  "*.cc",
  "*.cpp",
  "*.h",
  "*.hpp",
  "*.m",
  "*.mm",
  "*.rs",
  "*.go",
  "*.py",
  "*.rb",
  "*.erb",
  "*.php",
  "*.smali"
];

const DEFAULT_EXCLUDES = [
  "!.git/**",
  "!.kuzushi/**",
  "!.joern/**",
  "!**/node_modules/**",
  "!**/target/debug/**",
  "!**/target/release/**",
  "!**/build/**",
  "!**/dist/**",
  "!**/poc/**",
  "!**/apktool_out/**",
  "!GPATH",
  "!GTAGS",
  "!GRTAGS"
];

export function runRg(target, args, options = {}) {
  const result = spawnSync(resolveRg(), args, {
    cwd: target,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 100 * 1024 * 1024
  });
  if (result.error) {
    return { ok: false, status: null, stdout: result.stdout ?? "", stderr: result.error.message };
  }
  return {
    ok: result.status === 0 || result.status === 1,
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? ""
  };
}

// Build a globs+excludes argument list for rg. Pass {includeGlobs/excludeGlobs}
// to override the default include/exclude set.
export function buildGlobs(options = {}) {
  const includes = options.includeGlobs ?? DEFAULT_GLOBS;
  const excludes = options.excludeGlobs ?? DEFAULT_EXCLUDES;
  const args = [];
  for (const glob of includes) {
    args.push("-g", glob);
  }
  for (const glob of excludes) {
    args.push("-g", glob);
  }
  return args;
}

// Parse rg --json stdout into match records. Ignores summary/begin/end events
// and malformed lines so callers stay resilient to rg version drift.
export function parseJsonMatches(text, limit = 200) {
  const hits = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (event.type !== "match") continue;
    hits.push({
      filePath: event.data?.path?.text,
      line: event.data?.line_number,
      text: event.data?.lines?.text?.trim()
    });
    if (hits.length >= limit) break;
  }
  return hits;
}

// Ranking heuristics for rg hits. "generic" deprioritizes imports and tests;
// "payment-android" biases toward payment/service boundaries (used by x-ray's
// entry-point collection).
const rankers = {
  generic(hit) {
    const path = hit.filePath ?? "";
    const text = hit.text ?? "";
    let score = 0;
    if (/^import\s/.test(text)) score -= 20;
    if (/\/test\//i.test(path)) score -= 10;
    if (/\.spec\.|_test\.|test_/i.test(path)) score -= 10;
    return score;
  },
  "payment-android"(hit) {
    const path = hit.filePath ?? "";
    const text = hit.text ?? "";
    let score = 0;
    if (path.includes("/services/")) score += 40;
    if (/\/services\/(chase|firstdata|braintree|paypal|venmo)\//.test(path)) score += 60;
    if (/\/com\/lyft\/|\/me\/lyft\//.test(path)) score += 20;
    if (/FIRST_DATA_URL|ClientTokenizeCard|ChaseNetKeyApi|EncryptionListener|onEncryptionComplete|ProtectPANandCVV|PayPalClient|BraintreeClient|approvalUrl|redirectUri/.test(text)) score += 20;
    if (/^import\s/.test(text)) score -= 20;
    if (path.includes("/apktool_out/") || path.endsWith(".smali")) score -= 15;
    if (/\/(androidx|org\/chromium|io\/sentry|com\/google|kotlin|j\$)\//.test(path)) score -= 25;
    if (/events\/client|Companion|R\.java/.test(path)) score -= 30;
    return score;
  },
  // "systems" biases toward native boundaries, systems-language files, and
  // parser/decoder code (used by systems-hunt's candidate ranking).
  systems(hit) {
    const path = hit.filePath ?? "";
    const text = hit.text ?? "";
    let score = 0;
    if (/(System\.loadLibrary|JNIEXPORT|external fun|native\s+)/.test(text)) score += 40;
    if (/\.(c|cc|cpp|h|hpp|m|mm|rs)$/.test(path)) score += 25;
    if (/parser|decode|inflate|unmarshal|deserialize/i.test(text)) score += 20;
    if (/^import\s/.test(text)) score -= 20;
    if (/\/test\//i.test(path)) score -= 15;
    return score;
  }
};

export function rankHit(hit, profile = "generic") {
  return (rankers[profile] ?? rankers.generic)(hit);
}

// List the repository's source files. Prefers rg --files; if rg is unavailable
// (spawn error), falls back to a pure-Node recursive walk honoring the same
// include extensions and a directory-name subset of the default excludes.
export function listFiles(target, options = {}) {
  const result = runRg(target, ["--files", ...buildGlobs(options), "."]);
  if (result.ok) {
    return result.stdout.split(/\r?\n/).filter(Boolean);
  }
  return walkFilesFallback(target, options);
}

function globsToExtensions(globs) {
  return new Set(
    globs
      .map((glob) => (glob.startsWith("*.") ? glob.slice(1) : null))
      .filter(Boolean)
  );
}

const FALLBACK_EXTENSIONS = globsToExtensions(DEFAULT_GLOBS);

const FALLBACK_EXCLUDE_DIRS = new Set([
  ".git",
  ".kuzushi",
  ".joern",
  "node_modules",
  "build",
  "dist",
  "poc",
  "apktool_out"
]);

function extensionsFor(options) {
  if (!options.includeGlobs) return FALLBACK_EXTENSIONS;
  return globsToExtensions(options.includeGlobs);
}

// Pure-Node recursive walk. Best-effort: skips unreadable directories rather
// than throwing, so a single permission error can't abort the inventory.
function walkFilesFallback(target, options = {}) {
  const extensions = extensionsFor(options);
  const out = [];
  const stack = [target];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (FALLBACK_EXCLUDE_DIRS.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        const dot = entry.name.lastIndexOf(".");
        if (dot === -1) continue;
        if (extensions.has(entry.name.slice(dot))) {
          out.push(relative(target, full).split(sep).join("/"));
        }
      }
    }
  }
  return out;
}
