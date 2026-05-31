# kuzushi LLM-in-the-loop eval — discover lane — real CVEs

Model: **sonnet** · lane: **discover** · reps/case: **1** · cases: **9** · maxFiles: 12 · timeout: **45m/agent** · total cost: **$3.71**

These numbers are the REAL agents (fuzz-discoverer) run blind via `claude -p`,
not human-authored drafts. Small-N and nondeterministic — directional, not a leaderboard.
`routed` = the recon surfaced the vulnerable file as a seed (info only — this lane is
routing-INDEPENDENT); `found`/`confirmed` = a fuzz-discover finding reached **proven** on
the vulnerable file by a real sanitizer abort (the headline metric); `extra` = proven
findings off the expected anchor (a false-positive proxy / bonus bug).

| Case | expected file | routed | found | confirmed | extra-confirmed (FP proxy) |
|---|---|---|---|---|---|
| minimist-CVE-2020-7598 | `index.js` | 0/1 | 1/1 | 1/1 | 0.0 |
| redis-cve-2025-46817 | `deps/lua/src/lbaselib.c` | 0/1 | 0/1 | 0/1 | 0.0 |
| redis-cve-2025-46818 | `src/config.c` | 0/1 | 0/1 | 0/1 | 1.0 |
| redis-cve-2025-46819 | `deps/lua/src/llex.c` | 0/1 | 0/1 | 0/1 | 1.0 |
| redis-CVE-2025-49844-lua-rce | `deps/lua/src/lparser.c` | 0/1 | 0/1 | 0/1 | 1.0 |
| redis-CVE-2025-62507-xackdel-overflow | `src/t_stream.c` | 0/1 | 1/1 | 1/1 | 0.0 |
| redis-cve-2026-23479 | `src/blocked.c` | 0/1 | 0/1 | 0/1 | 0.0 |
| redis-cve-2026-23631 | `src/replication.c` | 0/1 | 0/1 | 0/1 | 0.0 |
| redis-cve-2026-25243 | `src/rdb.c` | 0/1 | 0/1 | 0/1 | 0.0 |
| **overall** | | **0%** | **22%** | **22%** | |

