# Launch kit

Copy-paste posts + a distribution checklist to get kuzushi in front of the people who star
security tooling. **Honesty is the hook** — the security crowd upvotes tools that admit their
limits. Every claim below is true and reproducible; keep it that way.

## The one-liner (use everywhere)
> Security review inside Claude Code that **proves it or drops it** — it reconstructs the exploit,
> proves the bug with a sandboxed PoC, validates the patch, and **benchmarks its own recall** so it
> can tell you what it missed.

---

## Show HN

**Title:**
`Show HN: Kuzushi – a Claude Code security plugin that proves bugs with a sandboxed PoC`

**Body:**
> Every AI security tool I tried cries wolf, so I built one that has to *prove* each bug it reports
> before it counts — and I made it score its own recall against planted CVEs so I'd know when it's
> lying to me.
>
> Kuzushi runs inside Claude Code on source you already have checked out. A finding doesn't get to
> be "real" because a scanner matched a pattern — it climbs a proof ladder: trace the source→sink
> path → reconstruct a concrete exploit → run it in a network-denied sandbox (a crash/sanitizer
> abort is the proof) → generate a patch and re-run the exploit to confirm the fix. Everything stays
> local under `.kuzushi/` with provenance.
>
> The part I'm most proud of is the measurement. There's a deterministic recall gate in `npm test`
> (it runs the real producers against planted bugs *and* decoys, at file- and line-level), and a
> billed LLM-in-the-loop eval against real fix-derived CVEs. I'll be blunt: the blind find-rate on a
> hard 9-CVE Redis set is ~22% — routing is mostly solved, but reasoning on subtle lifetime/
> integer-overflow bugs is still a wall, which is exactly why those get driven to *execution proof*
> instead of being confirmed by reading. The roadmap and the run-by-run numbers (including the
> misses) are in the repo.
>
> It borrows techniques from the AIxCC playbook — obligation discharge, sanitizer execution proof,
> and a scalable "light CPG" dataflow lane (build a Joern CPG scoped to one subsystem in seconds
> instead of the whole repo in minutes).
>
> Repo: https://github.com/allsmog/kuzushi-security-plugin — feedback (and bugs it misses) very welcome.

**Tips:** post 8–10am ET Tue–Thu; reply to every comment fast; lead replies with specifics, never
defensiveness. If someone says "22% is low," agree and explain the structural reason — that earns
trust here.

---

## r/netsec (and r/programming as a softer cross-post)

**Title:** `Kuzushi: an AI security pipeline that proves each bug with a sandboxed PoC and measures its own recall`

**Body:** same as Show HN, trimmed. r/netsec rewards rigor and reproducibility — lead with the
proof ladder + the zero-false-proof gate + the honest eval numbers. Link the `eval/README.md`
scoreboard directly; that page is the credibility.

---

## Lobsters
Tag `security` + `ai`. Lobsters dislikes hype — use the plain one-liner and link the eval log.

---

## Steady-drip distribution (do these once, they keep paying out)
- **PR onto curated lists** (each merge is a recurring star source):
  - `awesome-claude-code`, `awesome-mcp-servers`, `awesome-claude-code-plugins`
  - `awesome-security`, `awesome-appsec`, `awesome-static-analysis`
- **Anthropic / Claude Code Discord** — share in the plugins/show-and-tell channel with the demo GIF.
- **X/Twitter + Bluesky** — a thread: the proof ladder (with the GIF), then the honesty angle
  ("here's what it misses"), then the AIxCC-techniques angle. Tag the AppSec/AI-security crowd.
- **A short blog post / dev.to** titled "I made my AI security tool grade its own homework" — the
  measurement story is the differentiated content nobody else is writing.

## Profile + repo hygiene (free, do today)
- Pin the repo on your GitHub profile.
- Keep the `About` + topics current (already set).
- Add a `CONTRIBUTING.md` and a couple of `good first issue`s — contributors become stargazers.
- Put the demo GIF at the very top of the README (see DEMO.md).

## Things NOT to do
No buying stars, no astroturfing, no fake testimonials, no overclaiming the find-rate. The whole
brand is "this tool won't lie to you" — don't let the marketing be the thing that lies.
