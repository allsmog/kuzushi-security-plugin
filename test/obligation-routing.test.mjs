// Obligation-routed overlay (roadmap Phase 1). Pins the measured-correct design: the
// overlay covers the LONG TAIL (files below the file-read budget), never re-covers a file
// the file lane already reads, and ranks dangerous sites by class so a high-value
// obligation in a low-ranked file still surfaces.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rankObligations, _internals } from "../scripts/lib/obligation-routing.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-oblrt-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function write(t, rel, body) { const p = join(t, rel); mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); }

test("overlay surfaces a dangerous site in a low-ranked file (routing-independent)", () => {
  const t = repo();
  // An entry-point-dense file the file lane ranks high (will be EXCLUDED from the overlay).
  write(t, "api.js", "app.post('/a',(q,r)=>{}); app.get('/b',(q,r)=>{}); app.put('/c',(q,r)=>{});\n");
  // A plain helper with NO ranking signal but a dangerous command-exec site.
  write(t, "util/helper.js", "function run(host){ exec(`ping ${host}`); }\n");
  const r = rankObligations(t, { excludeTopFiles: 1, maxObligations: 20 });
  const hit = r.obligations.find((o) => o.filePath === "util/helper.js" && o.kind === "command-exec");
  assert.ok(hit, "the low-ranked file's command-exec obligation is in the overlay");
  assert.ok(hit.priority >= _internals.CLASS_WEIGHT["command-exec"], "priority reflects class weight");
});

test("overlay never re-covers a file the file lane already reads (no Tier-1 loss)", () => {
  const t = repo();
  // Two files, both with obligations; the higher-ranked one must be excluded by the overlay.
  write(t, "handler.js", "app.post('/x',(q,r)=>{}); exec(req.body.cmd);\n"); // entry-dense → top rank
  write(t, "lib/low.js", "function f(s){ eval(s); }\n");                     // no rank signal
  const r = rankObligations(t, { excludeTopFiles: 1, maxObligations: 20 });
  const files = new Set(r.obligations.map((o) => o.filePath));
  assert.ok(!files.has("handler.js"), "the file-lane-covered top file is excluded from the overlay");
  assert.ok(files.has("lib/low.js"), "the sub-budget file is covered by the overlay");
  assert.equal(r.excludedFiles, 1);
});

test("overlay is empty when excludeTopFiles covers everything (honest, no double work)", () => {
  const t = repo();
  write(t, "only.js", "function f(s){ exec(s); }\n");
  const r = rankObligations(t, { excludeTopFiles: 999, maxObligations: 20 });
  assert.equal(r.obligations.length, 0, "nothing left once all files are file-lane-covered");
});
