// Contract for the /fix adversarial re-attack (1.3): the deterministic selector that
// decides which OTHER findings get replayed against a patched copy. A patch that stops
// the original PoC can still leave a sibling bug in the SAME function reachable; the
// re-attack catches that. The selector is pure (reads findings + resolves the enclosing
// function from disk), so it's tested here without compiling/running anything — the
// execution + sanitizer-verdict path reuses the already-covered sandbox machinery.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { siblingFindingsForPatch } from "../scripts/cmd/fix-finalize.mjs";

// A C file with TWO functions so we can prove same-fn vs different-fn discrimination.
function repoTwoFns() {
  const t = mkdtempSync(join(tmpdir(), "kz-reattack-"));
  mkdirSync(join(t, "src"), { recursive: true });
  writeFileSync(join(t, "src", "stream.c"),
    "void xackdel(int n) {\n  char ids[8];\n  for (int j = 0; j < n; j++) {\n    ids[j] = j;\n  }\n}\n" +
    "void other(int m) {\n  char buf[4];\n  buf[m] = 0;\n}\n");
  return t;
}
const pocBlock = { harnessDir: "/tmp/does-not-need-to-exist", runCommand: "./h", language: "c" };

test("re-attack selector: a sibling PoC in the SAME function is selected", () => {
  const t = repoTwoFns();
  const fix = { fingerprint: "fix1", source: "systems-hunt", evidence: [{ filePath: "src/stream.c", startLine: 3 }] };
  const sibling = { fingerprint: "sib1", source: "deep-scan", evidence: [{ filePath: "src/stream.c", startLine: 4 }], poc: pocBlock };
  const sibs = siblingFindingsForPatch(t, [fix, sibling], fix);
  assert.equal(sibs.length, 1);
  assert.equal(sibs[0].fingerprint, "sib1", "the same-function sibling is replayed");
});

test("re-attack selector: a finding in a DIFFERENT function is NOT selected", () => {
  const t = repoTwoFns();
  const fix = { fingerprint: "fix1", evidence: [{ filePath: "src/stream.c", startLine: 3 }] };
  const elsewhere = { fingerprint: "elsewhere", evidence: [{ filePath: "src/stream.c", startLine: 9 }], poc: pocBlock };
  assert.deepEqual(siblingFindingsForPatch(t, [fix, elsewhere], fix), []);
});

test("re-attack selector: a sibling WITHOUT a runnable PoC is skipped", () => {
  const t = repoTwoFns();
  const fix = { fingerprint: "fix1", evidence: [{ filePath: "src/stream.c", startLine: 3 }] };
  const noPoc = { fingerprint: "nopoc", evidence: [{ filePath: "src/stream.c", startLine: 4 }] }; // no poc block
  assert.deepEqual(siblingFindingsForPatch(t, [fix, noPoc], fix), []);
});

test("re-attack selector: the finding being fixed never replays itself", () => {
  const t = repoTwoFns();
  const fix = { fingerprint: "fix1", evidence: [{ filePath: "src/stream.c", startLine: 3 }], poc: pocBlock };
  assert.deepEqual(siblingFindingsForPatch(t, [fix], fix), []);
});
