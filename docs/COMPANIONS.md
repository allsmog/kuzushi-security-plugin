# Companion skills

kuzushi is a focused white-box pipeline; it deliberately doesn't try to be every security tool.
Several **[Trail of Bits skills](https://github.com/trailofbits/skills)** (CC-BY-SA 4.0) cover
gaps kuzushi leaves open, and they install cleanly *alongside* this plugin — both are Claude Code
marketplaces, so you can run them in the same session.

```
/plugin marketplace add trailofbits/skills
/plugin menu          # browse and install individual plugins
```

## Recommended companions (and the kuzushi gap each fills)

| Trail of Bits plugin | Fills this gap |
|---|---|
| `insecure-defaults` | Hardcoded credentials, fallback secrets, weak crypto defaults, permissive CORS — config-level issues kuzushi's taint/threat hunts don't target. |
| `differential-review` | Per-PR / per-diff security review with git-history + blast-radius analysis. kuzushi reviews whole repos; this is the change-focused complement. |
| `supply-chain-risk-auditor` | Dependency takeover / exploitation risk. kuzushi's `/threat-intel` checks CVEs, not the supply-chain threat landscape. |
| `c-review` | Deep C/C++ review agents (memory/type/concurrency, OS-specific). Pairs with `/systems-hunt` when the target is C/C++-heavy. |
| `constant-time-analysis`, `zeroize-audit` | Crypto timing side-channels and sensitive-data zeroization — kuzushi has no crypto-specific analysis. |
| `sharp-edges` | Footgun / error-prone API and dangerous-configuration detection. |
| `firebase-apk-scanner` | Android APK Firebase misconfiguration — complements kuzushi's mobile entry-point patterns. |

## How they fit together

A typical combined flow: run kuzushi's pipeline (`/threat-model` → `/threat-hunt` /
`/taint-analysis` / `/systems-hunt` → `/verify` → `/variant-hunt`) for the white-box
source→sink work, and reach for the companions for the orthogonal angles — config defaults,
supply chain, crypto, and per-PR diffs.

## Note on overlap

Some Trail of Bits skills overlap kuzushi by design (`variant-analysis`, `static-analysis`,
`fp-check`, `audit-context-building`). kuzushi has its own first-class versions of these wired
into its findings pipeline — see the README. The companions above are the ones that fill genuine
*gaps* rather than duplicate. Use whichever fits your workflow; they don't conflict.

> Trail of Bits' skills are CC-BY-SA 4.0 and are **not** bundled into this MIT repo — install
> them from their marketplace. See [HARDENING.md](HARDENING.md) for the
> `enableAllProjectMcpServers` setting to keep third-party MCP servers from auto-loading.
