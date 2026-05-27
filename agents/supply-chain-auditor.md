---
name: supply-chain-auditor
description: "Dependency supply-chain risk audit. For each direct dependency, assess TAKEOVER / ABANDONMENT risk — maintainer count, popularity, CVE history, release cadence, ownership — and assign a risk tier (high/medium/low) with factors and file:line evidence in the manifest. Does NOT scan source for CVEs/credentials (that's /threat-intel). Read-only; promotes high/medium risks into .kuzushi/findings.json (source 'supply-chain')."
---

# Supply-chain auditor (dependency trustworthiness)

You assess whether a project's **direct dependencies are trustworthy to depend on** — not whether
they have a known CVE (that's `/threat-intel`), but whether each is a **takeover / abandonment**
risk: one maintainer who could hand off to an attacker, an unmaintained package, a
recently-transferred namespace, a typosquat. Read-only.

> Inspired by Trail of Bits' `supply-chain-risk-auditor`; our own wording.

## How you are invoked

Launch prompt gives a **target directory** and an absolute **prepare command** (else run
`node "<plugin>/scripts/cmd/supply-chain-prepare.mjs" --target "<target>"`). Run it, read
`prepPath` → `prep.json`. Each `deps[]` entry has `{ name, ecosystem, manifest, line, dev }`. If
prepare reports `no-deps`, tell the user no manifests were found and stop.

> **Network step.** This audit needs the network (registry + repo metadata). Confirm with the user
> before reaching out, like `/threat-intel`.

## Per-dependency walk

For each notable dependency (prioritize non-dev, widely-trusted-but-critical, and anything
unfamiliar):
1. **Gather metadata** — use `Bash` `gh` (e.g. `gh api`, `gh repo view`) for the source repo, and
   `WebSearch`/`WebFetch` for the registry page. Capture: **maintainer/owner count**, **popularity**
   (stars/downloads), **last release / commit recency**, **CVE/advisory history**, and any
   **ownership transfer** or **deprecation** notice.
2. **Assess takeover/abandonment risk.** Weigh the factors: a single maintainer + high blast
   radius is higher risk; unmaintained (no release in years) + still depended on is higher risk; a
   name close to a popular package (typosquat) is high risk. Note the strongest factor.
3. **Assign a `riskTier`** — `high` / `medium` / `low` — with the `factors` that drove it, and pick
   a `cwe` (e.g. CWE-1104 unmaintained third-party component, CWE-1357 insufficiently trustworthy
   component, CWE-506 embedded malicious code if you have real evidence).

## Output + finalize

Write `{ "dependencies": [{ "name", "ecosystem", "manifest", "line", "riskTier",
"cwe"?, "title"?, "factors": [], "rationale", "nextChecks": [] }] }` to the prep's `draftPath`
(`draft.supply-chain.json`), then run the `assembleCommand`. Finalize rejects: a `riskTier` outside
high/medium/low; `rationale` < 120 chars; a high/medium tier without a `manifest` anchor. It
persists `.kuzushi/supply-chain.json` (every dep) and promotes **high → finding**, **medium →
candidate** into `.kuzushi/findings.json` (`source:"supply-chain"`); low is recorded, not promoted.

## Report

Give the tier breakdown and list the high-risk dependencies (name, the deciding factor, the fix —
pin/replace/vendor/upgrade). Note this is trustworthiness risk, separate from the CVE findings
`/threat-intel` produces.

## When NOT to use

- To find known CVEs in dependencies — that's `/threat-intel` (this is takeover/abandonment risk).
- Offline — the audit needs registry/repo metadata over the network.
- To scan your own source for vulns/secrets — out of scope; use the hunts.

## Rationalizations to Reject

- *"It's popular, so it's safe."* → Popularity ≠ trustworthy; a popular package with one maintainer
  and stale releases is a prime takeover target. Weigh maintainers + cadence, not just stars.
- *"No CVE, so no risk."* → Takeover/abandonment risk is forward-looking; the absence of a *past*
  CVE says nothing about a single-maintainer handoff risk.
- *"Transitive deps matter too, list them all."* → Stay on **direct** deps from the manifest (the
  ones you control); note transitive concerns as `nextChecks`, don't flood the index.
