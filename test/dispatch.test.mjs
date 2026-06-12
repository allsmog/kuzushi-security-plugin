// Tests for the general dispatch / program-kind enumerator. The enumerator recovers the
// real attacker entry points that call-graph reachability scores ~0 (table-/registry-/
// convention-dispatched handlers) — the blind spot that buried the real Redis command
// handlers under a vendored RESP parser. These assert it generalizes (convention defs,
// {name,fn} table rows, registration calls) WITHOUT overfitting (a string→string data
// table is not a handler).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dispatchVocabulary, dispatchHandlerFiles, classifyProgramKind, detectSanitizerBuild } from "../scripts/lib/dispatch.mjs";

function fixture(files) {
  const t = mkdtempSync(join(tmpdir(), "kz-disp-"));
  for (const [p, c] of Object.entries(files)) {
    const fp = join(t, p);
    mkdirSync(join(fp, ".."), { recursive: true });
    writeFileSync(fp, c);
  }
  return t;
}

test("convention-named handler is enumerated from its DEFINITION (generated-table case)", () => {
  // The Redis shape: the command table is generated at build time (absent), but the handler
  // function xxxCommand is right there in source. That convention IS the signal.
  const t = fixture({
    "src/t_thing.c": "void thingConsumeCommand(client *c){char b[8];/* overflow */}\nvoid thingAddCommand(client *c){}\n",
    "src/server.c": "int main(int argc,char**argv){bind(0,0,0);listen(fd,5);return 0;}\n"
  });
  const names = dispatchVocabulary(t).map((e) => e.name);
  assert.ok(names.includes("thingconsume"), "thingConsumeCommand → thingconsume");
  assert.ok(names.includes("thingadd"), "thingAddCommand → thingadd");
  assert.ok([...dispatchHandlerFiles(t)].some((f) => /t_thing\.c$/.test(f)), "the handler's DEFINITION file is surfaced");
});

test("a { \"name\", fn } pointer-table row is enumerated (luaL_Reg / PyMethodDef shape)", () => {
  const t = fixture({
    "src/lib.c": "static int do_get(lua_State*L){return 0;}\nstatic const luaL_Reg R[]={{\"get\",do_get},{NULL,NULL}};\n"
  });
  const v = dispatchVocabulary(t);
  assert.ok(v.some((e) => e.name === "get" && e.handlerSymbol === "do_get"), "row { \"get\", do_get } → handler do_get");
});

test("a registration call register('name', fn) is enumerated", () => {
  const t = fixture({
    "src/m.c": "static int onLogin(req*r){return 0;}\nvoid setup(){register_command(\"login\", onLogin);}\n"
  });
  assert.ok(dispatchVocabulary(t).some((e) => e.name === "login"), "register_command(\"login\", onLogin) → login");
});

test("ANTI-OVERFIT: a string→string data table is NOT a handler", () => {
  const t = fixture({ "src/x.c": "const char *T[][2]={{\"a\",\"b\"},{\"c\",\"d\"}};\nstatic int OBJ_X=1;\n" });
  assert.equal(dispatchVocabulary(t).length, 0, "string→string rows have no function symbol → not handlers");
});

test("classifyProgramKind: main+socket ⇒ daemon; no main ⇒ library; main+argv ⇒ cli", () => {
  assert.equal(classifyProgramKind(fixture({ "s.c": "int main(int c,char**v){listen(1,2);accept(1,0,0);return 0;}\n" })).kind, "daemon");
  assert.equal(classifyProgramKind(fixture({ "lib.c": "int add(int a,int b){return a+b;}\n" })).kind, "library");
  assert.equal(classifyProgramKind(fixture({ "c.c": "int main(int argc,char**argv){getopt(argc,argv,\"x\");return 0;}\n" })).kind, "cli");
});

test("detectSanitizerBuild prefers the project's OWN sanitizer switch", () => {
  const t = fixture({ "Makefile": "SANITIZER?=\nall:\n\t$(CC) x.c\n", "x.c": "int main(){}\n" });
  assert.match(detectSanitizerBuild(t).command, /SANITIZER=address/);
  const cm = fixture({ "CMakeLists.txt": "project(x)\n", "x.c": "int main(){}\n" });
  assert.match(detectSanitizerBuild(cm).command, /fsanitize=address/);
});

test("interpreter dispatch-table declaration (luaL_Reg) routes the file even when its handlers aren't in the def index", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { dispatchHandlerFiles, enumerateDispatch } = await import("../scripts/lib/dispatch.mjs");
  const t = mkdtempSync(join(tmpdir(), "kz-disp-tbl-"));
  mkdirSync(join(t, "deps", "lua", "src"), { recursive: true });
  // A vendored interpreter file that DECLARES a handler table but whose handler bodies are
  // elsewhere (mimics the large-repo case where the def index is capped before reaching it).
  writeFileSync(join(t, "deps", "lua", "src", "lbaselib.c"),
    "static const luaL_Reg base_funcs[] = {\n  {\"assert\", luaB_assert},\n  {\"print\", luaB_print},\n  {NULL, NULL}\n};\n");
  // A pure data table must NOT be mistaken for a handler table (anti-overfit guard).
  writeFileSync(join(t, "deps", "lua", "src", "data.c"),
    "static const char *const names[] = { \"a\", \"b\", \"c\" };\n");
  const files = dispatchHandlerFiles(t, {});
  assert.ok(files.has("deps/lua/src/lbaselib.c"), "luaL_Reg declaration routes the file");
  assert.ok(!files.has("deps/lua/src/data.c"), "a plain string array is not a handler table");
  const decl = enumerateDispatch(t, {}).find((e) => e.kind === "handler-table-decl");
  assert.ok(decl && /luaL_Reg/.test(decl.signal), "the table-decl signal names the type");
});
