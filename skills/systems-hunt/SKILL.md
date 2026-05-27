---
name: systems-hunt
description: Native / parser / memory-safety review. Scans the repo for systems patterns (loadLibrary/JNI, memcpy/Unsafe/gets, archive parsers, deserialization, exec), then the systems-hunter agent confirms reachability + memory-safety impact and promotes verdicts to .kuzushi/findings.json. Most useful on C/C++/Rust/native code.
context: fork
agent: systems-hunter
user-invocable: true
---

# Systems hunt

Run the native / memory-safety review for the current repository.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/systems-hunt-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":30}'`). Read the prep's `prepPath`.
2. For **each** candidate, do the per-candidate walk (reach → memory-safety impact → guards →
   verdict) using `tree_sitter:callers`/`query` and `codeql:query`/`joern:query` if a DB/CPG
   exists. Use each candidate's `id` as `candidateId`.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` (finalize) — it validates verdicts and promotes them into
   `.kuzushi/findings.json` (`source:"systems-hunt"`).
4. Report verdict counts and the `exploitable` findings (id, CWE, source→sink + the missing
   bounds check).
