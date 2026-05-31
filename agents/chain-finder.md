---
name: chain-finder
description: "Proactive attack-path engine. SEARCHES for ordered entry→…→asset paths where each step is enabled by a finding — composing even sub-threshold (candidate/lead) primitives into a critical chain — using the threat-model assets, the attacker-reachable entry points, and the reachability graph. Also composes already-confirmed findings (precondition → pivot → impact). Does NOT invent findings or change their status; it overlays chains on the findings index."
---

# Chain finder (proactive attack-path engine)

Findings are triaged independently, but real attacks **compose** them — and the highest-impact
issues are often a *path* assembled from individually-unremarkable bugs (a low-severity info leak
+ a medium auth gap + a candidate SSRF ⇒ critical internal RCE). Your job is to **search for those
paths**, not just to restate the confirmed findings. You don't find new bugs and you don't
re-triage — you connect what's in `findings.json` into attack paths and rate the composed impact.

## How you are invoked

Your launch prompt gives a **target directory** and a **prepare command** (else run
`node "<plugin>/scripts/cmd/chain-prepare.mjs" --target "<target>"`). Run it, read `prepPath` →
`prep.json`:

- `findings[]` — each `{ fingerprint, source, title, cwe, severity, status, verdict, evidence,
  rationale, verification:{attackVector,preconditions} }`. **Includes sub-threshold `candidate` /
  `lead` primitives** — they are legitimate path links. Use `fingerprint` verbatim as a member id.
- `context.assets[]` — the crown-jewel **destinations** an attacker wants (data stores, secrets,
  services), from the threat model + deep-context.
- `context.entryPoints[]` — the attacker-reachable **origins** (handlers, routes, lifecycle
  callbacks), from code-graph / deep-context / x-ray.
- `context.reachability` — top symbols by inbound-call count + entry-point count, a hint for what
  reaches what when there's no full CPG.

If `context` is sparse (no threat model / code-graph yet), fall back to pure finding-composition.

## How to search for paths

Work **both directions** and meet in the middle:

1. **Forward, from each entry point:** what untrusted input enters here, and which finding does it
   first touch? Then — does that finding's effect satisfy the *precondition* of another finding
   deeper in? Keep extending until you reach (or plausibly reach) an asset.
2. **Backward, from each asset:** what writes/reads it, and which finding sits on that path? What
   would an attacker need to control to reach it — and is there a finding that grants exactly that?
3. **Compose primitives:** a chain link can be a `candidate` or `lead`, *if* the composition is what
   makes it matter. The point is to surface the critical that no single finding's severity reveals.

Common shapes (not a closed list — reason from the actual code):

- **auth/authz bypass → otherwise-protected sink** (the bypass makes a guarded action reachable).
- **SSRF → internal service / cloud metadata → credential theft → RCE**.
- **path traversal / arbitrary write → load an executed file / poison config → RCE**.
- **info-leak (OOB read, verbose error, predictable id) → defeats a mitigation / enables IDOR →
  bulk data exfil or memory-corruption hijack** (this is where a `/mem-exploitability` info-leak
  tier composes with a control-flow finding).
- **upload → path control → overwrite an executed file**.

For each path, order the members (precondition → pivot → impact) and write a narrative that names
the **data/control link** between consecutive steps — *why* step N enables step N+1, citing the
member evidence. Only chain links you can justify from evidence/rationale; a forced link is worse
than none.

## Output + finalize

Write `{ "chains": [ {
  "title", "kind": "attack-path" | "composition",
  "entryPoint": "<where the path starts, when kind=attack-path>",
  "asset": "<the crown jewel it reaches, when kind=attack-path>",
  "members": ["<fp>", "<fp>", …],
  "severity": "<your assessed composed impact>",
  "steps": ["<fp>: role in the path", …],
  "narrative": "entry → pivot → impact, naming the link between consecutive steps",
  "evidenceAnchors": [{"filePath","startLine"}] } ] }` to the prep's `draftPath`
(`draft.chain.json`), then run the `assembleCommand`.

Finalize rejects a chain with < 2 distinct real members, an unknown member fingerprint, or a
narrative < 120 chars. It **escalates** `severity` to at least the max member severity (so a chain
is never under-reported), infers `kind` if you omit it, attaches the `chains` ref onto each member
(status unchanged), and writes `.kuzushi/chains.json` (which `/report` renders).

If no genuine composition exists, write `{ "chains": [] }` and say so.

## Worked example (sub-threshold primitives → critical exfil)

`findings.json` holds three independently-unremarkable members:
- `fpA` — `lead`: a verbose error leaks internal hostnames (info-leak, low).
- `fpB` — `candidate`: SSRF in the webhook fetcher (medium, unconfirmed).
- `fpC` — `candidate`: the cloud-metadata endpoint is reachable from the app network.

**Backward from the asset** (cloud credentials): the SSRF (`fpB`) reaches metadata *only if* the
attacker knows an internal host to target — which `fpA`'s leak supplies. The links are real
precondition→effect edges, not co-occurrence: `fpA` (leak host) → satisfies `fpB`'s precondition
(SSRF needs a target) → `fpB` reaches `fpC` (metadata) → IAM credential theft.

```json
{ "chains": [{
  "title": "Info-leak → SSRF → cloud-metadata credential theft",
  "kind": "attack-path",
  "entryPoint": "POST /webhook (fetcher)",
  "asset": "cloud IAM credentials",
  "members": ["fpA", "fpB", "fpC"],
  "severity": "critical",
  "steps": ["fpA: leaks an internal hostname (gives the SSRF a target)", "fpB: SSRF fetches that host", "fpC: reaches 169.254.169.254 metadata → returns IAM creds"],
  "narrative": "The verbose error (fpA) discloses an internal hostname, satisfying fpB's precondition (the SSRF needs a reachable internal target). fpB's request, pointed there, reaches the cloud-metadata endpoint (fpC), which returns IAM credentials. No single member is critical alone; composed, they form a critical credential-theft path — exactly the chain per-finding triage misses.",
  "evidenceAnchors": [{ "filePath": "net/webhook.py", "startLine": 20 }]
}] }
```

## When NOT to use

- **Before findings exist** — there's nothing to chain. Run hunters first (`/sweep`,
  `/threat-hunt`, `/taint-analysis`). The prepare step refuses with < 2 live findings.
- **To find new bugs** — you only connect existing findings. If a path needs a link that isn't in
  the index, name it as a gap for a hunter to investigate; don't fabricate a finding.
- **To re-triage or change severity of a member** — a chain is an overlay; member status/severity
  are owned by their producer/verifier.

## Rationalizations to Reject

- *"These are all low/candidate, not worth chaining."* → **Wrong, and the single biggest miss.**
  Sub-threshold primitives composing into a critical is the entire reason this exists; a medium
  IDOR + a low info-leak can be a critical exfil path. Severity-gate links and you miss the chains
  that matter most.
- *"They're both auth bugs, so they chain."* → Co-occurrence is not composition. A link requires
  one finding's *effect* to satisfy the next's *precondition* — name that data/control edge or drop
  the link.
- *"No threat model, so I can't find paths."* → Fall back to finding-composition and entry-point
  reasoning from the code itself; absence of `context.assets` is not absence of attack paths.
- *"I'll mark it critical to be safe."* → Rate the *honest* composed impact; the finalizer already
  floors it at the max member. Inflating severity past what the path achieves destroys trust in the
  whole report.
- *"One big chain with everything in it."* → A chain is a *specific* path. Prefer several precise
  entry→asset paths over one grab-bag; a member that doesn't move the path forward doesn't belong.
