# Awesome-list PRs (paste-ready)

Each merged entry is a recurring, passive star source. Submit one PR per list. **Always read that
list's `CONTRIBUTING.md` first** — formats differ (some use a bullet, some an alphabetized table,
`awesome-static-analysis` uses a YAML data file). Entries below are written to drop in with minimal
edits. Keep descriptions honest — these lists' maintainers reject hype.

## Reusable one-liner
> AI security pipeline for Claude Code that proves each bug with a sandboxed PoC and benchmarks its
> own recall. Local-first, network-denied by default. MIT.

## PR title (reuse)
`Add kuzushi (local-first AI security pipeline for Claude Code)`

## PR body (reuse, trim per list)
> Adds [kuzushi](https://github.com/allsmog/kuzushi-security-plugin), a local-first security-review
> pipeline that runs inside Claude Code. It hunts source→sink bugs, **proves** each one with a
> sandboxed PoC (a crash/sanitizer abort is the evidence), validates the fix against the exploit, and
> **benchmarks its own recall** against planted CVEs (it reports its misses). MIT, Node ≥20,
> static-first with sandboxed dynamic proof. Slots into the `<SECTION>` section.

---

## Targets, entries, and where they go

### 1. awesome-claude-code  ·  `hesreallyhim/awesome-claude-code`
Section: a plugins / tooling list (check current headings).
```markdown
- [kuzushi](https://github.com/allsmog/kuzushi-security-plugin) — Local-first security-review plugin: hunts source→sink bugs, proves them with a sandboxed PoC, validates the patch, and benchmarks its own recall.
```

### 2. awesome-claude-code-plugins / awesome-claude-code-agents (if present)
Section: security.
```markdown
- [kuzushi-security-plugin](https://github.com/allsmog/kuzushi-security-plugin) — Source→sink hunting, sandboxed PoC proof, PoC⁺-validated patches; benchmarks its own recall. Local-first, MIT.
```

### 3. awesome-mcp-servers  ·  `punkpeye/awesome-mcp-servers`
Section: 🛡️ Security (kuzushi ships self-gating stdio MCP servers wrapping tree-sitter/Semgrep/CodeQL/Joern). Match their emoji/format.
```markdown
- [allsmog/kuzushi-security-plugin](https://github.com/allsmog/kuzushi-security-plugin) 🏠 🍎 🐧 🪟 — Security-review pipeline (tree-sitter/Semgrep/CodeQL/Joern MCP servers) that proves bugs with a sandboxed PoC and measures its own recall.
```
*(🏠 = local service; OS icons per their legend — adjust to match.)*

### 4. awesome-static-analysis  ·  `analysis-tools-dev/awesome-static-analysis`
This list uses a structured **YAML data file** (`data/tools/*.yml` or similar) + a website. Add an
entry like this and let CI render it:
```yaml
- name: kuzushi
  categories:
    - linter        # use their nearest categories: security / sast
  languages:
    - c
    - cpp
    - javascript
    - python
    - go
    - java
  other:
    - security
  licenses:
    - MIT
  types:
    - cli
  homepage: https://github.com/allsmog/kuzushi-security-plugin
  source: https://github.com/allsmog/kuzushi-security-plugin
  description: "Local-first AI security pipeline for Claude Code: source→sink hunting plus sandboxed PoC proof; benchmarks its own recall against planted CVEs."
```
*(Match their exact schema/keys — copy a neighboring entry as the template.)*

### 5. awesome-security  ·  `sbilly/awesome-security`
Section: Tools → SAST / Source Code Analysis.
```markdown
- [kuzushi](https://github.com/allsmog/kuzushi-security-plugin) - Local-first AI security-review pipeline (Claude Code) that proves source→sink bugs with a sandboxed PoC and benchmarks its own recall.
```

### 6. awesome-appsec  ·  `paragonie/awesome-appsec`
Section: Tools (or Static Analysis).
```markdown
* [kuzushi](https://github.com/allsmog/kuzushi-security-plugin) - Proves each finding with a sandboxed PoC and validates the patch against the exploit; measures its own recall. Local-first, MIT.
```

### 7. awesome-devsecops  ·  `TaptuIT/awesome-devsecops` (or `devsecops/awesome-devsecops`)
Section: SAST / Security as Code.
```markdown
- [kuzushi](https://github.com/allsmog/kuzushi-security-plugin) - Source→sink hunting with sandboxed PoC proof and PoC⁺-validated patches; SARIF output for CI. Benchmarks its own recall.
```

---

## Order to do them
Start with the **Claude Code** and **MCP** lists (best audience fit, fastest merges), then the
broad security lists (`awesome-security`, `awesome-appsec`, `awesome-static-analysis`). One PR at a
time, each linking the eval scoreboard so maintainers can see the honest numbers.
