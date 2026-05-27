---
name: traffic-map
description: Offline Burp/HAR import — parse a captured traffic export (HAR JSON or Burp "Save items" XML), correlate observed endpoints to source handlers (x-ray + code-graph), and flag the gaps it reveals (shadow surface, unauthenticated mutating endpoints, params reaching sinks). Writes .kuzushi/traffic-map.json and promotes gaps into findings (source "traffic-map"). Offline only — no proxy, no live requests. Pass a capture via --input '{"file":"capture.har"}'.
context: fork
agent: traffic-mapper
user-invocable: true
---

# Traffic map (ground review in observed traffic)

Turn a Burp/HAR capture into a source-grounded attack-surface map — the static-respecting way to
use the dynamic half of a review.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/traffic-map-prepare.mjs" --target "<repo root>"`
   (it auto-discovers `*.har` / Burp XML, or pass `--input '{"file":"capture.har"}'`). If it reports
   `no-capture`, tell the user to point at a HAR/Burp export and stop. Read the prep's `prepPath`.
2. For each observed endpoint, correlate it to the source handler (match `handlerHints`, confirm
   with route-pattern search). Record `mapped` / `shadow` / `no-traffic`. Then flag only the gaps
   the *traffic* reveals: mutating endpoints with no authz, shadow admin/debug endpoints, observed
   params that reach a sink (hand source→sink to `/verify` via nextChecks).
3. Write the `{ correlations: [...], candidates: [...] }` bundle to the prep's `draftPath`, then run
   the `assembleCommand` — it persists `.kuzushi/traffic-map.json` and promotes the candidates into
   `.kuzushi/findings.json` (`source:"traffic-map"`).
4. Report endpoints observed, mapped/shadow counts, and the flagged gaps. The map grounds
   `/threat-model` and `/threat-hunt`.

## When NOT to use

- With no capture — this needs a HAR or Burp "Save items" XML; it does not browse the app.
- As a live DAST/proxy — it's strictly offline correlation of an existing capture to source.

## Rationalizations to Reject

- *"Endpoint observed, so flag it."* → Only raise a candidate where the traffic adds signal
  (no-authz mutation, shadow surface, param→sink); a normal mapped GET is just a correlation.
- *"No handler ⇒ finding."* → A `shadow` endpoint may be a reverse-proxied service outside this repo;
  flag only if clearly in-scope.
- *"This param is exploitable."* → Hand the source→sink to `/verify` as a next-check; don't assert it here.
