// Contract for cheap cross-file reachability (crossFileCallers). It must find a
// symbol's call sites in OTHER files (the depth a single-file tree-sitter callers
// query can't reach) and exclude the definition line. Skips if ripgrep is absent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crossFileCallers, isCalledElsewhere } from "../scripts/lib/callgraph.mjs";
import { ripgrepPath } from "../scripts/lib/ripgrep.mjs";
import { spawnSync } from "node:child_process";

const rgOk = (() => { try { return spawnSync(ripgrepPath(), ["--version"], { stdio: "ignore" }).status === 0; } catch { return false; } })();

test("crossFileCallers finds call sites in other files, not the definition", { skip: !rgOk }, () => {
  const t = mkdtempSync(join(tmpdir(), "kz-cg-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src/db.js"), "export function runQuery(sql){ return raw(sql); }\n");
  writeFileSync(join(t, "src/handler.js"), "import {runQuery} from './db';\nfunction h(q){ return runQuery('SELECT '+q); }\n");

  const callers = crossFileCallers(t, "runQuery");
  const inHandler = callers.find((c) => c.filePath === "src/handler.js");
  assert.ok(inHandler, "found the cross-file call site in handler.js");
  assert.ok(!callers.some((c) => /export function runQuery/.test(c.text)), "definition line excluded");
  assert.equal(isCalledElsewhere(t, "runQuery", "src/db.js"), true);
});
