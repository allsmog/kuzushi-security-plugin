import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RUNTIME_ROOTS = [
  ".claude-plugin",
  "agents",
  "commands",
  "hooks",
  "mcp",
  "scripts",
  "skills"
];
const SKIP_DIRS = new Set(["node_modules", "vendor", "workspace", ".git"]);
const TEXT_EXTS = new Set([".js", ".mjs", ".cjs", ".json", ".md"]);
const BANNED = [
  { name: "claude -p", re: /\bclaude\s+-p\b/ },
  { name: "spawn claude", re: /\bspawn(?:Sync)?\(\s*["']claude["']/ },
  { name: "exec claude", re: /\bexec(?:File)?(?:Sync)?\(\s*["']claude["']/ }
];

function ext(path) {
  const i = path.lastIndexOf(".");
  return i >= 0 ? path.slice(i) : "";
}

function* walk(dir) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (ent.isDirectory()) {
      if (!SKIP_DIRS.has(ent.name)) yield* walk(join(dir, ent.name));
      continue;
    }
    if (ent.isFile()) yield join(dir, ent.name);
  }
}

test("runtime plugin code does not shell out to claude -p", () => {
  const hits = [];
  for (const root of RUNTIME_ROOTS) {
    const absRoot = join(ROOT, root);
    if (!existsSync(absRoot)) continue;
    const files = statSync(absRoot).isDirectory() ? walk(absRoot) : [absRoot];
    for (const file of files) {
      if (!TEXT_EXTS.has(ext(file))) continue;
      const text = readFileSync(file, "utf8");
      for (const banned of BANNED) {
        if (banned.re.test(text)) hits.push(`${relative(ROOT, file)}: ${banned.name}`);
      }
    }
  }

  assert.deepEqual(hits, [], "eval/test harnesses may use claude -p, but runtime plugin code must rely on Claude Code skills/agents");
});
