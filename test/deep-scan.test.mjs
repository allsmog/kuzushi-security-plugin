// Contracts for /deep-scan — the whole-file deep reader. The prepare must produce a
// risk-RANKED file list (security-relevant / entry-point files first) with an honest
// unreadCount, and the finalize must promote read-derived hypotheses while gating
// bad verdicts and finding-without-CWE. This is the producer that removes the
// pattern-gating recall ceiling, so its determinism (ranking + validation) matters.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { storeFor } from "../scripts/lib/artifact-store.mjs";
import { rankFiles } from "../scripts/lib/risk-rank.mjs";
import { prepareDeepScan } from "../scripts/cmd/deep-scan-prepare.mjs";
import { finalizeDeepScan } from "../scripts/cmd/deep-scan-finalize.mjs";
import { extractObligations } from "../scripts/lib/sink-obligations.mjs";

function repo() {
  const t = mkdtempSync(join(tmpdir(), "kz-deep-"));
  mkdirSync(join(t, ".kuzushi"), { recursive: true });
  return t;
}
function emptyFindings(t) {
  writeFileSync(storeFor(t).findingsPath, JSON.stringify({ version: "1.0", schemaVersion: "findings.v1", target: t, findings: [] }) + "\n");
}
function write(t, rel, body) {
  const abs = join(t, rel); mkdirSync(join(abs, ".."), { recursive: true }); writeFileSync(abs, body);
}
function writeDraft(runDir, name, obj) { writeFileSync(join(runDir, name), JSON.stringify(obj)); }
function findings(t) { return JSON.parse(readFileSync(storeFor(t).findingsPath, "utf8")).findings; }
function expectReject(fn) {
  const orig = process.exit;
  process.exit = (code) => { throw new Error(`process.exit(${code})`); };
  try { assert.throws(fn, /process\.exit\(1\)/); } finally { process.exit = orig; }
}
const LONG = "x".repeat(160);

// --- lifetime-free obligation (the UAF lever) — unit-gate the new rule ----------------------
test("obligations: a free() emits a lifetime-free obligation; a commented free does not", () => {
  const t = repo();
  write(t, "src/c.c", "void g(struct s *p){\n  free(p);\n  // free(p)\n  return;\n}\n");
  const free = extractObligations(t, "src/c.c").filter((o) => o.kind === "lifetime-free");
  assert.equal(free.length, 1, "the real free() is flagged, the comment is not");
  assert.equal(free[0].line, 2);
});

test("obligations: a realloc(n*sz) line tags alloc-arith, not lifetime-free (first-match ordering)", () => {
  const t = repo();
  write(t, "src/r.c", "void f(int n,int sz){ char *p = realloc(p, n*sz); }\n");
  const obs = extractObligations(t, "src/r.c");
  assert.ok(obs.some((o) => o.kind === "alloc-arith"), "realloc tags alloc-arith");
  assert.ok(!obs.some((o) => o.kind === "lifetime-free"), "and NOT lifetime-free — the more specific rule wins first");
});

// --- int-overflow-size obligation (the CWE-190→OOB lever; the 46819 class the fuzzer can't reach) ---
// Vuln→obligation / safe→no-obligation pair. The shape is structural (a length minus a product, or a
// multiply/shift in an index) — never the CVE literal — so it generalizes past the Lua lexer.
test("obligations: a `len - 2*(2+sep)` length-math line emits int-overflow-size; a plain `len - sep` does not", () => {
  const t = repo();
  // vuln shape: a narrow `int sep` accumulator drives a length computed by subtracting a product (the
  // exact arithmetic family of CVE-2025-46819's read_long_string, written generically).
  write(t, "src/vuln.c", "char *take(char *b, size_t blen, int sep){\n  return newstr(b + (2 + sep), blen - 2*(2 + sep));\n}\n");
  const vuln = extractObligations(t, "src/vuln.c").filter((o) => o.kind === "int-overflow-size");
  assert.equal(vuln.length, 1, "the length-minus-a-product line is flagged once");
  assert.equal(vuln[0].line, 2, "flagged at the arithmetic line");
  // safe shape: same length cue, but a guarded plain subtraction — no product, no overflow-prone op.
  write(t, "src/safe.c", "char *take2(char *b, size_t blen, size_t sep){\n  if (sep >= blen) return 0;\n  return b + blen - sep;\n}\n");
  const safe = extractObligations(t, "src/safe.c").filter((o) => o.kind === "int-overflow-size");
  assert.equal(safe.length, 0, "a plain guarded `blen - sep` is NOT flagged (no product/shift)");
});

test("obligations: a multiply inside an array index emits int-overflow-size", () => {
  const t = repo();
  write(t, "src/idx.c", "void s(char *a, int i, int w){\n  a[i * w] = 0;\n}\n");
  const io = extractObligations(t, "src/idx.c").filter((o) => o.kind === "int-overflow-size");
  assert.equal(io.length, 1, "an `a[i * w]` index multiply is flagged");
});

test("obligations: malloc(n*sz) stays alloc-arith, not int-overflow-size (first-match ordering)", () => {
  const t = repo();
  write(t, "src/m.c", "void f(int n,int sz){ char *p = malloc(n * sz); }\n");
  const obs = extractObligations(t, "src/m.c");
  assert.ok(obs.some((o) => o.kind === "alloc-arith"), "malloc-family arithmetic wins as alloc-arith");
  assert.ok(!obs.some((o) => o.kind === "int-overflow-size"), "and NOT int-overflow-size — the alloc rule is earlier");
});

test("obligations: even-stride sampling reaches late-file free sites (cap not top-biased — the xackdel property)", () => {
  const t = repo();
  const lines = Array.from({ length: 120 }, (_, i) => `  free(p${i});`); // 120 lifetime-free sites spread down the file
  write(t, "src/long.c", `void f(){\n${lines.join("\n")}\n}\n`);
  const obs = extractObligations(t, "src/long.c", { cap: 32 });
  assert.equal(obs.length, 32, "capped to 32");
  assert.ok(obs.every((o) => o.kind === "lifetime-free"), "all free sites tagged lifetime-free");
  const maxLine = Math.max(...obs.map((o) => o.line));
  assert.ok(maxLine > 90, `even-stride reaches the late file (max sampled free at line ${maxLine} of ~122), not just the first 32`);
});

test("risk-rank: security-relevant files outrank boring ones", () => {
  const t = repo();
  write(t, "src/auth/login.js", "function login(){}\n");   // security-relevant path
  write(t, "src/util/format.js", "function fmt(){}\n");     // boring
  const { ranked } = rankFiles(t, { maxFiles: 10 });
  const auth = ranked.find((r) => r.filePath === "src/auth/login.js");
  const util = ranked.find((r) => r.filePath === "src/util/format.js");
  assert.ok(auth && util, "both ranked");
  assert.ok(auth.score > util.score, "the auth file scores higher");
  assert.ok(auth.reasons.includes("security-relevant-path"));
});

test("deep-scan prepare: ranks files, reports unreadCount honestly under a budget", () => {
  const t = repo();
  for (let i = 0; i < 6; i += 1) write(t, `src/m${i}.js`, `function f${i}(){}\n`);
  write(t, "src/payment.js", "function charge(){}\n");
  const prep = prepareDeepScan(t, { maxFiles: 3 });
  assert.equal(prep.status, "prepared");
  assert.equal(prep.fileCount, 3, "budget respected");
  assert.ok(prep.unreadCount >= 4, "the rest are reported as unread, not dropped silently");
  const doc = JSON.parse(readFileSync(prep.prepPath, "utf8"));
  assert.equal(doc.files[0].filePath, "src/payment.js", "highest-risk file read first");
});

test("deep-scan prepare writes an auditable obligation ledger artifact", () => {
  const t = repo();
  write(t, "src/native.c", [
    "void f(char *p){",
    "  char buf[16];",
    "  free(p);",
    "}"
  ].join("\n"));
  const prep = prepareDeepScan(t, { maxFiles: 5 });
  const store = storeFor(t);
  assert.equal(prep.obligationLedgerPath, store.obligationLedgerPath);
  assert.equal(prep.obligationsJsonlPath, store.obligationsJsonlPath);
  assert.ok(existsSync(store.obligationLedgerPath), "ledger JSON is persisted under .kuzushi");
  assert.ok(existsSync(store.obligationsJsonlPath), "ledger JSONL is persisted under .kuzushi");

  const ledger = JSON.parse(readFileSync(store.obligationLedgerPath, "utf8"));
  assert.equal(ledger.schemaVersion, "obligation-ledger.v1");
  assert.ok(ledger.summary.routedRecords >= 1, "at least one dangerous site is routed");
  assert.ok(ledger.records.every((r) => ["routed", "deferred"].includes(r.status)), "records have auditable terminal states");
  assert.ok(ledger.records.some((r) => r.class === "lifetime-free"), "the free() obligation is recorded");
});

test("deep-scan prepare writes function-scoped obligation slices", () => {
  const t = repo();
  write(t, "src/native.c", [
    "static int helper(char *p){",
    "  if (!p) return 0;",
    "  free(p);",
    "  return 1;",
    "}",
    "void unrelated(void){}"
  ].join("\n"));
  const prep = prepareDeepScan(t, { maxFiles: 5, maxSliceLines: 20 });
  assert.ok(existsSync(prep.obligationSlicesPath), "global slices artifact is persisted");
  assert.ok(existsSync(prep.obligationSlicesRunPath), "run-local slices artifact is persisted");

  const slices = JSON.parse(readFileSync(prep.obligationSlicesPath, "utf8"));
  assert.equal(slices.schemaVersion, "obligation-slices.v1");
  assert.ok(slices.sliceCount >= 1);
  const lifetime = slices.slices.find((s) => s.class === "lifetime-free");
  assert.ok(lifetime, "free() gets a function-scoped slice");
  assert.equal(lifetime.excerpt.filePath, "src/native.c");
  assert.ok(lifetime.excerpt.lines.some((l) => /static int helper/.test(l.text)), "slice includes the enclosing function header");
  assert.ok(!lifetime.excerpt.lines.some((l) => /unrelated/.test(l.text)), "slice does not spill into unrelated function");
});


test("deep-scan finalize: promotes a read-derived finding; DROPS (not rejects) bad verdict + finding w/o CWE", () => {
  const t = repo(); emptyFindings(t);
  write(t, "src/api.js", "function run(q){ return db.run('SELECT '+q); }\n");
  const prep = prepareDeepScan(t, { maxFiles: 5 });

  // A valid deep-read finding (a custom db.run() wrapper no pattern would catch).
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "d1", bugClass: "sqli", verdict: "finding", severity: "high", cwe: "CWE-89",
      title: "SQLi via custom db.run wrapper",
      rationale: `run(q) concatenates the untrusted q directly into a SQL string passed to the project's db.run helper; no parameterization or escaping anywhere on the path ${LONG}`,
      selfCheck: "A parameterized query or an escaping/whitelist guard would make this safe; neither is present on the path from q to db.run.",
      evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }
  ] });
  const res = finalizeDeepScan(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.equal(findings(t).filter((f) => f.source === "deep-scan").length, 1);

  // finding without a CWE is DROPPED (not promoted) — finalize still completes.
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "d2", verdict: "finding", rationale: LONG, evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }
  ] });
  const r2 = finalizeDeepScan(t, prep.runDir);
  assert.equal(r2.status, "completed");
  assert.equal(r2.droppedCount, 1);
  assert.ok(!findings(t).some((f) => f.refId === "d2"), "finding without CWE is not promoted");

  // bad verdict is DROPPED too.
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [{ deepId: "d3", verdict: "nope", rationale: LONG }] });
  const r3 = finalizeDeepScan(t, prep.runDir);
  assert.equal(r3.droppedCount, 1);
  assert.ok(!findings(t).some((f) => f.refId === "d3"), "bad-verdict item is not promoted");

  const drops = readFileSync(storeFor(t).droppedCandidatesPath, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.ok(drops.some((d) => d.source === "deep-scan" && d.id === "d2" && /requires a cwe/.test(d.reason)), "missing-CWE drop is in the shared ledger");
  assert.ok(drops.some((d) => d.source === "deep-scan" && d.id === "d3" && /invalid verdict/.test(d.reason)), "bad-verdict drop is in the shared ledger");
});

test("deep-scan finalize: a finding without selfCheck is DROPPED (self-falsification gate, item-scoped)", () => {
  const t = repo(); emptyFindings(t);
  write(t, "src/api.js", "function run(q){ return db.run('SELECT '+q); }\n");
  const prep = prepareDeepScan(t, { maxFiles: 5 });
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "x", verdict: "finding", cwe: "CWE-89", rationale: LONG,
      evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] }  // no selfCheck
  ] });
  const res = finalizeDeepScan(t, prep.runDir);
  assert.equal(res.droppedCount, 1);
  assert.ok(!findings(t).some((f) => f.refId === "x"), "finding without selfCheck is dropped, not promoted");
});

test("deep-scan finalize: ONE malformed item is dropped, the rest of the batch still promotes (the real-run bug)", () => {
  const t = repo(); emptyFindings(t);
  write(t, "src/api.js", "function run(q){ return db.run('SELECT '+q); }\n");
  const prep = prepareDeepScan(t, { maxFiles: 5 });
  writeDraft(prep.runDir, "draft.deep-scan.json", { candidates: [
    { deepId: "good", verdict: "finding", cwe: "CWE-89", title: "real OOB",
      rationale: `a genuine finding whose rationale clears the depth gate ${LONG}`,
      selfCheck: "Parameterization would make this safe; confirmed absent on the path from q to the db.run helper.",
      evidenceAnchors: [{ filePath: "src/api.js", startLine: 1 }] },
    { deepId: "short", verdict: "rejected", rationale: "too short to clear the 150-char gate" } // invalid sibling
  ] });
  const res = finalizeDeepScan(t, prep.runDir);
  assert.equal(res.status, "completed");
  assert.equal(res.promotedCount, 1);
  assert.equal(res.droppedCount, 1);
  assert.equal(res.dropped[0].id, "short");
  assert.ok(findings(t).some((f) => f.refId === "good"), "the valid finding survives its malformed sibling");
});

test("risk-rank: an entry-point-dense file outranks a keyword-only file (reachability over keyword)", () => {
  const t = repo();
  // handler.js DEFINES routes (attacker surface) but has no security keyword in its path
  write(t, "lib/handler.js", "app.post('/a',(q,r)=>{}); app.get('/b',(q,r)=>{}); app.put('/c',(q,r)=>{});\n");
  // auth_helpers.js matches the keyword hint but defines no entry points
  write(t, "lib/auth_helpers.js", "function fmt(s){ return s.trim(); }\n");
  const { ranked } = rankFiles(t, { maxFiles: 10 });
  const h = ranked.find((r) => r.filePath === "lib/handler.js");
  const a = ranked.find((r) => r.filePath === "lib/auth_helpers.js");
  assert.ok(h && a, "both ranked");
  assert.ok(h.score > a.score, "entry-point-dense file outranks the keyword-only file");
  assert.ok(h.reasons.some((x) => x.startsWith("entry-defs")), "entry-defs is the reason");
});

test("deep-scan prep carries the lens taxonomy and a focused lens filters obligations (Lever 4)", () => {
  const t = repo();
  emptyFindings(t);
  // A native file with a lifetime (free→use) site and a buffer site.
  write(t, "src/m.c", [
    "void f(char *p){",
    "  char buf[CAP];",
    "  free(p);",
    "  use(p);",
    "}"
  ].join("\n"));
  const all = prepareDeepScan(t, { maxFiles: 5 });
  const ap = JSON.parse(readFileSync(all.prepPath, "utf8"));
  assert.equal(ap.lens, null, "default pass is all-class (no lens)");
  assert.ok(ap.lenses.includes("lifetime") && ap.lenses.includes("memory"), "carries the lens taxonomy");

  const focused = prepareDeepScan(t, { maxFiles: 5, lens: "lifetime" });
  const fp = JSON.parse(readFileSync(focused.prepPath, "utf8"));
  assert.equal(fp.lens, "lifetime");
  const kinds = new Set(fp.files.flatMap((f) => (f.obligations || []).map((o) => o.kind)));
  assert.ok(kinds.has("lifetime-free"), "lifetime lens keeps the free→use site");
  assert.ok(!kinds.has("fixed-size-buffer"), "lifetime lens drops the non-lifetime buffer site");
});
