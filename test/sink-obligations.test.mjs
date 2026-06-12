// Obligation extractor — the AIxCC-style "discharge each dangerous site" checklist.
// Pins that obligations land on the actual bug lines for both the native (memory) and
// the web (injection/authz/logic) rule families. If a rule stops firing on a known site,
// the discovery agent silently loses that checklist item — so this is a real net.

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { extractObligations } from "../scripts/lib/sink-obligations.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function tmp(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "kz-obl-"));
  const p = join(dir, name);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
  return { dir, file: name };
}

function kindsAt(obs, line) {
  return obs.filter((o) => o.line === line).map((o) => o.kind);
}

test("web: SQL execution behind a wrapper yields a sql-sink obligation on the exact line", () => {
  const { dir, file } = tmp("dao.py", [
    "class DAO:",
    "    def run(self, sql):",
    "        return self._conn.cursor().execute(sql).fetchall()",
  ].join("\n"));
  const obs = extractObligations(dir, file);
  assert.ok(kindsAt(obs, 3).includes("sql-sink"), `expected sql-sink at line 3, got ${JSON.stringify(obs)}`);
});

test("web: command exec and object-authz fire; comments are ignored", () => {
  const { dir, file } = tmp("h.js", [
    "// exec('rm -rf /')  <- a comment, must NOT fire",
    "const { exec } = require('child_process');",
    "exec(`ping -c 1 ${host}`);",
    "const order = Order.findById(req.params.id);",
  ].join("\n"));
  const obs = extractObligations(dir, file);
  assert.equal(kindsAt(obs, 1).length, 0, "comment line must yield no obligation");
  assert.ok(kindsAt(obs, 3).includes("command-exec"));
  assert.ok(kindsAt(obs, 4).includes("object-authz"));
});

test("web: path-fs, ssrf, deserialization, dynamic-eval each fire", () => {
  const { dir, file } = tmp("v.py", [
    "import os, pickle, requests",
    "send_file(os.path.join(BASE, name))",        // 2: path-fs
    "requests.get(user_url)",                       // 3: ssrf
    "pickle.loads(blob)",                           // 4: deserialization
    "eval(expr)",                                   // 5: dynamic-eval
  ].join("\n"));
  const obs = extractObligations(dir, file);
  assert.ok(kindsAt(obs, 2).includes("path-fs"));
  assert.ok(kindsAt(obs, 3).includes("ssrf"));
  assert.ok(kindsAt(obs, 4).includes("deserialization"));
  assert.ok(kindsAt(obs, 5).includes("dynamic-eval"));
});

test("native: memory rules still fire (no regression from the web extension)", () => {
  const { dir, file } = tmp("m.c", [
    "void f(char *src, int n) {",
    "    char buf[CAP];",         // 2: fixed-size-buffer (named-constant bound)
    "    memcpy(buf, src, n);",   // 3: raw-copy
    "    free(p); use(p);",       // 4: lifetime-free
  ].join("\n"));
  const obs = extractObligations(dir, file);
  assert.ok(kindsAt(obs, 2).includes("fixed-size-buffer"));
  assert.ok(kindsAt(obs, 3).includes("raw-copy"));
  assert.ok(kindsAt(obs, 4).includes("lifetime-free"));
});

test("a plain text / unknown extension yields no obligations", () => {
  const { dir, file } = tmp("notes.txt", "exec('x'); pickle.loads(y); free(p);");
  assert.deepEqual(extractObligations(dir, file), []);
});

test("the bundled web bench fixtures route obligations to their planted bug lines", () => {
  // idor-py: the IDOR is the object fetched by user id at orders.py:5.
  const idor = extractObligations(join(ROOT, "bench/cases/idor-py/repo"), "api/orders.py");
  assert.ok(idor.some((o) => o.line === 5 && o.kind === "object-authz"));
  // python-path-traversal: the traversal sink is send_file(join(BASE,name)) at files.py:13.
  const pt = extractObligations(join(ROOT, "bench/cases/python-path-traversal/target"), "files.py");
  assert.ok(pt.some((o) => o.line === 13 && o.kind === "path-fs"));
});

test("gc-rooting fires on allocating/GC-stepping Lua calls, NOT on inert accessors (de-noise)", () => {
  const { dir, file } = tmp("g.c", [
    "int f (lua_State *L) {",
    "  int n = lua_gettop(L);",       // 2: accessor — must NOT fire
    "  if (!lua_toboolean(L, 1)) {}", // 3: accessor — must NOT fire
    "  lua_Number x = lua_tonumber(L, 2);", // 4: accessor — must NOT fire
    "  lua_newtable(L);",             // 5: allocates — MUST fire
    "  lua_pushstring(L, s);",        // 6: allocates — MUST fire
    "  TString *t = luaS_new(L, s);", // 7: allocates — MUST fire
  ].join("\n"));
  const obs = extractObligations(dir, file, { cap: 100 });
  const gc = new Set(obs.filter((o) => o.kind === "gc-rooting").map((o) => o.line));
  assert.ok(!gc.has(2) && !gc.has(3) && !gc.has(4), `accessors must not yield gc-rooting, got lines ${[...gc]}`);
  assert.ok(gc.has(5) && gc.has(6) && gc.has(7), `allocating calls must yield gc-rooting, got lines ${[...gc]}`);
});
