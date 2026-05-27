---
name: threat-intel
description: Research recent critical/high CVEs for this repo's stack and for similar apps in its domain, and distill them into checkable invariants written to .kuzushi/threat-intel.json. Uses live web search. Best run after /threat-model.
context: fork
agent: threat-intel-researcher
user-invocable: true
---

# Threat intel research

Research the CVE threat landscape for the current repository and write
`.kuzushi/threat-intel.json`.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/threat-intel-prepare.mjs" --target "<repo root>"`
   and parse its `scope` + stage paths.
2. Research **critical/high** CVEs for the detected stack (version-checked against the
   manifests) and CVE *classes* seen in **similar apps**, using WebSearch/WebFetch. Cross-
   reference the threat model if present.
3. Write the three stage files (`intel-stack-cves.json`, `intel-similar-apps.json`,
   `intel-invariants.json`) — the invariants carry source/sink/sanitizer signals + CWE so
   `/invariant-test` can check them.
4. Run the `assembleCommand` to persist `.kuzushi/threat-intel.json`.
5. Report the counts and the top applicable CVEs + highest-value invariants. Then mention
   that `/invariant-test` can now verify those invariants against the code.
