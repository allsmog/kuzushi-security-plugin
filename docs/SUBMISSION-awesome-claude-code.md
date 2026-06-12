# Submission: awesome-claude-code (46k★, best-fit list)

**This list forbids PR/CLI submissions** (their CONTRIBUTING: *"ALL RECOMMENDATIONS MUST BE MADE
USING THE WEB UI ISSUE FORM… OR YOU RISK BEING BANNED. Do not open a PR. It is not possible to
submit via the `gh` CLI."*). So this can't be automated — but every field is pre-filled below.
Their bot validates format and auto-opens the PR once a maintainer approves.

**→ Open the form (must be the github.com web UI, logged in as you):**
https://github.com/hesreallyhim/awesome-claude-code/issues/new?template=recommend-resource.yml

Paste these field-for-field. Claims are evidence-backed and disclosures are honest, as the list
explicitly requires.

---

- **Display Name:** `kuzushi`
- **Category:** `Agent Skills` *(their note: plugins are filed here for now)*
- **Sub-Category:** `General`
- **Primary Link:** `https://github.com/allsmog/kuzushi-security-plugin`
- **Author Name:** `allsmog`
- **Author Link:** `https://github.com/allsmog`
- **License:** `MIT`

**Description:**
> A local-first security-review pipeline for Claude Code where findings must be **proven**, not just
> flagged. It hunts source→sink vulnerabilities across the repo, then advances each finding through a
> proof ladder: reconstruct the exploit → run it in a network-denied sandbox (a crash/sanitizer abort
> is the evidence) → generate a patch and re-run the exploit to confirm the fix. It also **benchmarks
> its own recall** against planted bugs + safe decoys, with a hard zero-false-proof gate, so it
> reports what it missed instead of crying wolf. Honest scope: blind find-rate on a hard real-CVE set
> is ~22% (published, with the misses, in `eval/README.md`) — it is strong at *verified, reproducible*
> review, not a magic bug finder.

**Validate Claims:** (all deterministic — no LLM/API needed)
> ```
> git clone https://github.com/allsmog/kuzushi-security-plugin
> cd kuzushi-security-plugin && npm install
> npm run bench:smoke   # the proof ladder: finding → confirmed → proven (+ zero-false-proof gate)
> npm run bench         # recall scoreboard on a planted-bug corpus (file- AND site-level)
> npm test              # 300+ tests incl. the live producer-firing recall gate
> ```
> The billed LLM-in-the-loop eval and its run-by-run numbers — **including the bugs it misses** — are
> in `eval/README.md` and `docs/WORLD-CLASS-DISCOVERY.md`.

**Specific Task(s):** Review a codebase for vulnerabilities and prove the real ones (then patch them).

**Specific Prompt(s):**
> In any source repo: `/sweep` (whole-repo hunt + verify), then `/report`. To see a bug that pattern
> scanners structurally miss, run it on the bundled `bench/cases/novel-wrapper-sqli/repo` — a SQL
> injection hidden behind a custom `dao.run()` wrapper that no regex matches.

**Additional Comments (disclosures — the list requires these):**
> - **Network:** only the optional `/threat-intel` and `/supply-chain` steps make web/GitHub calls,
>   and they ask first; everything else is offline, and `review-safe`/`ci-locked` profiles deny
>   network entirely.
> - **Code execution:** `/poc`, `/fuzz`, `/sanitize-pov` run harnesses in a Docker `--network none`
>   sandbox (or a consented local run) — never against your working tree, and only after you approve.
> - **Permissions:** does **not** require `--dangerously-skip-permissions` for normal use.
> - **Patches** are applied only behind explicit per-finding approval, to a sandbox copy first.
> - Repo is well over a week old (tagged releases since v0.5.0).

- **Checkboxes:** tick the Code-of-Conduct / guidelines confirmations.

---

## The other lists — honest assessment (do NOT blast PRs)
- **awesome-mcp-servers (89k★):** PR-able, but it's for *standalone MCP servers*; kuzushi only
  *bundles* MCP servers as a plugin → likely closed as off-topic. Skip unless reframed.
- **awesome-static-analysis (analysis-tools-dev):** legit fit (multi-language SAST). Uses a
  structured YAML data file + CI — a real PR is worth doing but must match their schema exactly;
  ask and I'll prepare/open it carefully.
- **awesome-security / awesome-appsec:** acceptable fits but slow/semi-stale; lower ROI than the
  Claude Code form above.
