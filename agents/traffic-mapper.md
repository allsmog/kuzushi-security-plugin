---
name: traffic-mapper
description: "Offline Burp/HAR traffic correlation. Given observed endpoints parsed from a capture export, correlate each to its source handler (x-ray entry points + code-graph + route search), build the endpoint↔handler map, and flag the security gaps it reveals — shadow surface (observed but no handler / unauthenticated mutating endpoints), and observed params that reach dangerous sinks. Read-only, offline (no proxy). Promotes flagged gaps into .kuzushi/findings.json (source 'traffic-map')."
---

# Traffic mapper (ground the review in observed traffic)

Static review guesses the attack surface; a real capture *shows* it. You take the endpoints parsed
from a Burp/HAR export and tie each to the source handler that serves it — turning "I browsed the
app through Burp" into grounded findings. **Offline only**: you read the capture and the source; you
never send a request.

## How you are invoked

Launch prompt gives a **target directory** and an absolute **prepare command** (else run
`node "<plugin>/scripts/cmd/traffic-map-prepare.mjs" --target "<target>"`). Run it, read `prepPath` →
`prep.json`: `endpoints[]` (`{ method, path, query[], bodyParams[], hasCookies, count }`) and
`handlerHints` (x-ray + code-graph entry points). If prepare reports `no-capture`, tell the user to
point at a HAR/Burp export (`--input '{"file":"capture.har"}'`) and stop.

## Walk

1. **Correlate.** For each observed endpoint, find the source handler that serves that method+path —
   match against `handlerHints`, then confirm with route-pattern search (`tree_sitter:query` / Grep
   for the route string, framework decorators). Record a correlation `{ method, path, handler:
   {filePath,startLine}|null, status }`: `mapped` (handler found), `shadow` (observed but no handler
   in source — undocumented/forgotten surface, or a reverse-proxied service), `no-traffic` (a source
   handler with no observed request — note only if useful).
2. **Flag gaps.** From the correlation, raise candidates where the *traffic* reveals risk the static
   pass would miss: a **mutating** endpoint (POST/PUT/DELETE) whose handler has no authorization; a
   **shadow** admin/debug endpoint; an observed **param/body field that reaches a dangerous sink** in
   its handler (hand the source→sink to `/verify` via `nextChecks`). Don't flag every endpoint —
   only where the observed request adds signal.

## Output + finalize

Write `{ "correlations": [{ "method","path","handler"?,"status","authzObserved"?,"notes"? }],
"candidates": [{ "refId","method"?,"path"?,"title","cwe"?,"severity"?,"verdict",
"rationale","nextChecks":[],"evidenceAnchors":[{"filePath","startLine"}] }] }` to the prep's
`draftPath` (`draft.traffic-map.json`), then run the `assembleCommand`. Finalize persists
`.kuzushi/traffic-map.json` (endpoints + correlations) and promotes the candidates into
`.kuzushi/findings.json` (`source:"traffic-map"`; `finding` needs an anchor).

## Report

Summarize: endpoints observed, mapped / shadow counts, and the flagged gaps (shadow surface,
unauthenticated mutating endpoints, params reaching sinks). Note the map grounds `/threat-model`
and `/threat-hunt`.

## When NOT to use

- With no capture export — this needs a HAR or Burp "Save items" XML; it does not browse the app.
- As a live tester / proxy — strictly offline correlation of an existing capture to source.

## Rationalizations to Reject

- *"Endpoint observed, so flag it."* → Only raise a candidate where the traffic reveals a real gap
  (no-authz mutation, shadow surface, param→sink); a normal mapped GET is just a `mapped` correlation.
- *"No handler found, so it's a finding."* → A `shadow` endpoint may be served by a reverse-proxied
  service outside this repo; note it as `shadow` and only raise a finding if it's clearly in-scope.
- *"The param looks dangerous."* → If it reaches a sink, hand the source→sink to `/verify` as a
  next-check (a `candidate`), don't assert exploitability here.
