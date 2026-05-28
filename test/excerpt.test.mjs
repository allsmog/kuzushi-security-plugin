// Contracts for the enclosing-function excerpt helper. It must widen the window
// from a hit line to the whole enclosing function (brace-matched for C-family,
// indentation for Python), cap pathological spans, and degrade to a fallback
// window when no block is found — so an agent sees the guard above and the logic
// below, not just ±10 lines.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { enclosingExcerpt } from "../scripts/lib/excerpt.mjs";

function repo(name, body) {
  const t = mkdtempSync(join(tmpdir(), "kz-ex-"));
  writeFileSync(join(t, name), body);
  return t;
}
function span(ex) {
  return { first: ex[0].line, last: ex[ex.length - 1].line, lines: ex.map((e) => e.text).join("\n") };
}

test("braces: JS — anchor inside a function returns the whole function incl. the guard above", () => {
  const src = [
    "import x from 'y';",            // 1
    "function handler(req, res) {",  // 2  <- header
    "  if (!req.user) return 403;",  // 3  <- guard above the sink
    "  const id = req.params.id;",   // 4
    "  const row = db.query(id);",   // 5  <- anchor (sink)
    "  return res.json(row);",       // 6
    "}",                              // 7  <- close
    "const other = 1;"               // 8
  ].join("\n");
  const t = repo("h.js", src);
  const s = span(enclosingExcerpt(t, "h.js", 5));
  assert.equal(s.first, 2, "starts at the function header");
  assert.equal(s.last, 7, "ends at the closing brace");
  assert.ok(s.lines.includes("if (!req.user)"), "the guard above the sink is visible");
  assert.ok(!s.lines.includes("const other = 1"), "stops at the function boundary");
});

test("indent: Python — anchor inside a def returns the whole def", () => {
  const src = [
    "import os",                       // 1
    "def checkout(request):",         // 2  <- header
    "    amount = request.amount",    // 3
    "    if amount < 0:",             // 4
    "        abort(400)",             // 5
    "    charge(card, amount)",       // 6  <- anchor
    "    return ok()",                // 7
    "",                                // 8 blank inside
    "def other():",                   // 9  <- next def (boundary)
    "    pass"                         // 10
  ].join("\n");
  const t = repo("p.py", src);
  const s = span(enclosingExcerpt(t, "p.py", 6));
  assert.equal(s.first, 2, "starts at def checkout");
  assert.ok(s.last >= 7 && s.last < 9, "ends before the next def");
  assert.ok(s.lines.includes("if amount < 0"), "the negative-amount guard is visible");
  assert.ok(!s.lines.includes("def other"), "stops before the next function");
});

test("fallback: unsupported/headerless file returns a ±window, not null", () => {
  const t = repo("notes.txt", Array.from({ length: 80 }, (_, i) => `line ${i + 1}`).join("\n"));
  const ex = enclosingExcerpt(t, "notes.txt", 40);
  assert.ok(ex && ex.length > 1, "non-empty excerpt");
  assert.ok(ex[0].line < 40 && ex[ex.length - 1].line > 40, "anchor is inside the window");
});

test("missing file returns null", () => {
  const t = repo("x.js", "x");
  assert.equal(enclosingExcerpt(t, "nope.js", 1), null);
});
