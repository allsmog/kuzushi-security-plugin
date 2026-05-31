// Contract for cheap cross-file reachability (crossFileCallers). It must find a
// symbol's call sites in OTHER files (the depth a single-file tree-sitter callers
// query can't reach) and exclude the definition line. Skips if ripgrep is absent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crossFileCallers, isCalledElsewhere, crossFileCallees, enclosingFunction, resolveDefinition } from "../scripts/lib/callgraph.mjs";
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

// ---- forward direction: crossFileCallees + enclosingFunction ----------------

function fixtureRepo() {
  const t = mkdtempSync(join(tmpdir(), "kz-callees-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src/db.js"), "export function runQuery(sql){ return raw(sql); }\n");
  writeFileSync(join(t, "src/svc.js"),
    "import {runQuery} from './db';\nexport function lookup(id){\n  const sql = 'SELECT '+id;\n  return runQuery(sql);\n}\n");
  writeFileSync(join(t, "src/handler.js"),
    "import {lookup} from './svc';\nfunction handle(req){\n  if (req && req.id) {\n    return lookup(req.id);\n  }\n}\n");
  return t;
}

test("crossFileCallees finds the callees of the enclosing function and resolves their defs", { skip: !rgOk }, () => {
  const t = fixtureRepo();
  const res = crossFileCallees(t, { filePath: "src/handler.js", line: 4 }); // the `return lookup(req.id)` line
  const names = res.callees.map((c) => c.name);
  assert.ok(names.includes("lookup"), "the cross-file callee is found");
  assert.ok(!names.includes("if") && !names.includes("return"), "control-flow keywords are not callees");
  assert.ok(!names.includes("handle"), "the function's own name (recursion guard) is excluded");
  const lookup = res.callees.find((c) => c.name === "lookup");
  assert.ok(lookup.defs.some((d) => d.filePath === "src/svc.js"), "the callee's definition resolves to svc.js");
});

test("crossFileCallees lets you walk a flow one more hop (svc → db)", { skip: !rgOk }, () => {
  const t = fixtureRepo();
  const res = crossFileCallees(t, { filePath: "src/svc.js", line: 4 }); // inside lookup(), the runQuery call
  const runQuery = res.callees.find((c) => c.name === "runQuery");
  assert.ok(runQuery, "lookup's callee runQuery is found");
  assert.ok(runQuery.defs.some((d) => d.filePath === "src/db.js"), "runQuery resolves to db.js — the next hop in the path");
});

test("enclosingFunction returns the block range and name (brace language)", { skip: !rgOk }, () => {
  const t = fixtureRepo();
  const fn = enclosingFunction(t, "src/handler.js", 4);
  assert.equal(fn.name, "handle");
  assert.ok(fn.startLine <= 2 && fn.endLine >= 4, `range ${fn.startLine}-${fn.endLine} should enclose the call on line 4`);
  assert.match(fn.text, /lookup\(req\.id\)/, "the body text includes the call");
});

test("crossFileCallees + enclosingFunction work for indentation languages (Python)", { skip: !rgOk }, () => {
  const t = mkdtempSync(join(tmpdir(), "kz-callees-py-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src/app.py"),
    "def handler(req):\n    data = parse(req)\n    return store(data)\n\ndef parse(x):\n    return x\n");
  const fn = enclosingFunction(t, "src/app.py", 2);
  assert.equal(fn.name, "handler");
  const res = crossFileCallees(t, { filePath: "src/app.py", line: 2 });
  const names = res.callees.map((c) => c.name).sort();
  assert.deepEqual(names, ["parse", "store"], "both callees found");
  const parse = res.callees.find((c) => c.name === "parse");
  assert.ok(parse.defs.length >= 1, "parse resolves (defined in the same file)");
  const store = res.callees.find((c) => c.name === "store");
  assert.deepEqual(store.defs, [], "store has no definition in-repo → empty defs (honest: unresolved)");
});

test("resolveDefinition excludes prototypes/calls (trailing ;) for C-family defs", { skip: !rgOk }, () => {
  const t = mkdtempSync(join(tmpdir(), "kz-resolve-"));
  writeFileSync(join(t, "a.c"), "int compute(int x);\nint compute(int x) {\n  return x + 1;\n}\nint main(){ return compute(2); }\n");
  const defs = resolveDefinition(t, "compute");
  assert.ok(defs.some((d) => /int compute\(int x\) \{/.test(d.text)), "the definition header is found");
  assert.ok(!defs.some((d) => /;\s*$/.test(d.text)), "the prototype (trailing ;) and the call are not defs");
});
