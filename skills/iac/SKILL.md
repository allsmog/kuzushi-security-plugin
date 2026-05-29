---
name: iac
description: Config & container security review. Scans Dockerfiles, Kubernetes/Compose manifests, and Terraform/IaC for misconfigurations (privileged containers, root, unpinned images, hardcoded secrets, public network/storage, disabled TLS); the iac-reviewer agent confirms each in context and promotes real ones into .kuzushi/findings.json (source "iac"). Distinct from /sast (source injection) and the insecure-defaults companion (app config values).
context: fork
agent: iac-reviewer
user-invocable: false
---

# IaC review

Review the deployment/config surface, not just the source.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/iac-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":30}'`). If it reports `no-candidates`, say there's no
   IaC/containers to review and stop. Read the prep's `prepPath`.
2. For **each** candidate, open the file and confirm it's a real misconfig in context (reject
   placeholders / `${VAR}` references / dev-only files). Decide `finding` / `candidate` / `rejected`
   across surfaces: container, secrets, network, cloud, transport, orchestration.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates and promotes into `.kuzushi/findings.json` (`source:"iac"`).
4. Report findings by surface (file:line, the misconfig, the secure setting).

## When NOT to use

- For first-party source vulnerabilities — that's `/threat-hunt`, `/taint-analysis`, `/sast`.
- On a repo with no Dockerfiles/manifests/Terraform — there's nothing to scan.

## Rationalizations to Reject

- *"`:latest` / root is fine in dev."* → Flag it unless the file is clearly dev-only; note the pin /
  non-root user.
- *"It's a placeholder password."* → A real committed credential is a finding; only `${VAR}` /
  placeholder references are `rejected`.
- *"0.0.0.0/0 is temporary."* → Public ingress to a sensitive port is a finding; name the scoped CIDR.
