---
name: dfd
user-invocable: false
description: Generate and print an ASCII data-flow diagram (DFD) of the target system — external entities, processes, data stores, data flows, and trust boundaries. Lightweight standalone artifact (no full PASTA threat model). Use when asked to "draw/show a DFD", "data flow diagram", or to quickly visualize trust boundaries and attacker-controlled flows. For threats + DFD together, use /threat-model.
argument-hint: "[focus, e.g. a subsystem or 'exploit path']"
allowed-tools: Bash, Read, Grep, Glob
---

# Data Flow Diagram (DFD)

Produce a standalone ASCII data-flow diagram of the system (scoped to the `$ARGUMENTS` focus,
if given). This is a quick visualization — it does **not** run the PASTA pipeline. For the full
threat model (named threats + DFD), use `/threat-model` instead.

## Steps

1. **Understand the system.** Reuse existing kuzushi artifacts when present
   (`.kuzushi/x-ray/x-ray.md`, `.kuzushi/deep-context.json`, `.kuzushi/threat-model.json`);
   otherwise read the code / binary analysis. Identify, with file:line (or function) evidence:
   - **external entities** — actors / clients / remote peers / input files that originate data
     from outside the trust boundary;
   - **processes** — the program and its handlers / functions / services that transform data;
   - **data stores** — files, DBs, in-memory buffers, heap/queue state the program holds;
   - **data flows** — who sends what to whom, over which channel (and how trusted the data is);
   - **trust boundaries** — process / network / privilege / allocator edges the data crosses.
   If `$ARGUMENTS` names a subsystem or scenario (e.g. an exploit path), scope the DFD to it.

2. **Write a DFD spec** to `.kuzushi/dfd.spec.json` (create `.kuzushi/` if needed). Shape:
   ```json
   {
     "title": "<system> - data flow diagram",
     "nodes": [
       {"id": "att", "name": "Remote client",    "type": "external_entity", "trustZone": "external"},
       {"id": "srv", "name": "Request handler",   "type": "process",         "trustZone": "internal"},
       {"id": "db",  "name": "State store",        "type": "data_store",      "trustZone": "internal"}
     ],
     "flows": [
       {"sourceId": "att", "targetId": "srv", "name": "request", "protocol": "tcp",
        "dataClassification": "untrusted", "trustBoundaryIds": ["tb_net"]},
       {"sourceId": "srv", "targetId": "db",  "name": "read/write"}
     ],
     "trustBoundaries": [
       {"id": "tb_net", "name": "network / process boundary",
        "outerZone": "external", "innerZone": "internal", "crossingFlowIds": ["...optional..."]}
     ]
   }
   ```
   - `type`: `external_entity` | `process` | `data_store`.
   - `trustZone`: any label (`external`, `dmz`, `entrypoint`, `internal`, `trusted`, ...);
     rendered grouped, ordered external → trusted.
   - Keep `id`s short (<= 6 chars) — flows and boundaries reference them.
   - Set `trustBoundaryIds` on every flow that crosses a boundary — those are the
     security-interesting flows and the renderer flags them.

3. **Render and print:**
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/dfd-render.mjs" \
     --in .kuzushi/dfd.spec.json --out .kuzushi/dfd.txt
   ```
   The script prints a connected, top-down ASCII diagram (boxes joined by labelled
   arrows; trust boundaries as dashed rules the flows cross) to stdout and saves it to
   `.kuzushi/dfd.txt`. Add `--ascii` for pure-ASCII glyphs on terminals that mangle Unicode.

   **PNG (optional, if the user wants an image):** render the same spec to a PNG with
   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/dfd-png.py" \
     --in .kuzushi/dfd.spec.json --out .kuzushi/dfd.png --scale 2
   ```
   (requires Pillow: `python3 -m pip install pillow`). Then surface the file to the user
   (e.g. send/attach `.kuzushi/dfd.png`) — don't try to paste an image into chat.

4. **Paste the rendered diagram into the chat verbatim, inside a triple-backtick fenced code
   block** (```). Mandatory — it is column-aligned ASCII and breaks if pasted as prose. Then add
   a 2-4 line note on the key trust boundaries and the most exposed (attacker-controlled) flow(s).

## Guidance

- Anchor nodes and flows in the actual code / kuzushi artifacts — do not invent architecture.
- One framed box per trust zone; cross-boundary flows are the ones worth scrutiny — make sure
  their `trustBoundaryIds` are set so they surface in the boundary list.
- For a binary / CTF target (no source repo), still model it: the attacker external entity, the
  process's input channels (stdin / argv / network), its in-memory data stores (heap / queue /
  parser state), and any allocator/privilege boundary the input crosses.

## When NOT to use

- To enumerate threats or run STRIDE — that's `/threat-model` (this skill only draws the DFD).
- To find concrete vulnerabilities — use `/threat-hunt`, `/taint-analysis`, `/systems-hunt`.
