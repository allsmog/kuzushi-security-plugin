#!/usr/bin/env node
// Standalone ASCII data-flow diagram (DFD) renderer.
//
// Reads a DFD spec JSON from --in <file> or stdin and prints a *connected*,
// top-down layered diagram (boxes joined by labelled arrows; trust boundaries as
// dashed rules) to stdout; optionally writes it to --out <file>. Self-contained:
// no kuzushi store / PASTA pipeline needed, so /dfd is a lightweight artifact.
//
//   --in <file>   read spec from file (else stdin)
//   --out <file>  also write the rendered diagram here
//   --ascii       pure-ASCII glyphs (+-|v>) instead of Unicode box-drawing
//
// Spec: { title, nodes:[{id,name,type,trustZone}],
//         flows:[{sourceId,targetId,name?,protocol?,dataClassification?,trustBoundaryIds?}],
//         trustBoundaries:[{id,name,outerZone,innerZone}] }
// node.type: external_entity | process | data_store (else => process)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const TYPE_TAG = {
  external_entity: "EE", external: "EE", actor: "EE", entity: "EE", client: "EE", user: "EE",
  process: "P", service: "P", component: "P", function: "P", handler: "P",
  data_store: "DS", datastore: "DS", database: "DS", store: "DS", file: "DS", buffer: "DS", memory: "DS",
};
const tag = (t) => TYPE_TAG[String(t ?? "").toLowerCase()] ?? "P";
const trunc = (s, m) => { s = String(s ?? ""); return s.length > m ? `${s.slice(0, m - 1)}…` : s; };

let G; // glyph set, chosen in render()
const UNI = { tl:"┌", tr:"┐", bl:"└", br:"┘", h:"─", v:"│", dn:"▼", rt:"►", tdn:"┬", tup:"┴", lj:"├", rj:"┤", x:"┼", b:"═" };
const ASC = { tl:"+", tr:"+", bl:"+", br:"+", h:"-", v:"|", dn:"v", rt:">", tdn:"+", tup:"+", lj:"+", rj:"+", x:"+", b:"=" };

function canvas() {
  const rows = [];
  const ensure = (y, x) => { while (rows.length <= y) rows.push([]); const r = rows[y]; while (r.length <= x) r.push(" "); };
  const set = (y, x, ch) => { if (y < 0 || x < 0) return; ensure(y, x); rows[y][x] = ch; };
  const text = (y, x, s) => { for (let i = 0; i < s.length; i++) set(y, x + i, s[i]); };
  const hline = (y, x1, x2) => { for (let x = Math.min(x1,x2); x <= Math.max(x1,x2); x++) if (rows[y]?.[x] !== G.v) set(y, x, G.h); };
  const vline = (x, y1, y2) => { for (let y = Math.min(y1,y2); y <= Math.max(y1,y2); y++) set(y, x, G.v); };
  const toString = () => rows.map((r) => r.join("").replace(/\s+$/g, "")).join("\n");
  return { set, text, hline, vline, toString };
}

function assignLayers(nodes, flows) {
  const ids = new Set(nodes.map((n) => n.id));
  const preds = new Map(nodes.map((n) => [n.id, 0]));
  for (const f of flows) if (ids.has(f.sourceId) && ids.has(f.targetId) && f.sourceId !== f.targetId) preds.set(f.targetId, preds.get(f.targetId) + 1);
  // sources are pinned at layer 0 and never pushed down by back-edges (e.g. output -> attacker)
  const pinned = new Set();
  const layer = new Map();
  for (const n of nodes) if (tag(n.type) === "EE" || (n.trustZone || "") === "external" || preds.get(n.id) === 0) { layer.set(n.id, 0); pinned.add(n.id); }
  if (!pinned.size) { layer.set(nodes[0].id, 0); pinned.add(nodes[0].id); }
  for (let it = 0; it < nodes.length + 2; it++) {
    let ch = false;
    for (const f of flows) {
      if (!ids.has(f.sourceId) || pinned.has(f.targetId)) continue;
      const ls = layer.get(f.sourceId); if (ls === undefined) continue;
      if ((layer.get(f.targetId) ?? -1) < ls + 1) { layer.set(f.targetId, ls + 1); ch = true; }
    }
    if (!ch) break;
  }
  for (const n of nodes) if (!layer.has(n.id)) layer.set(n.id, 0);
  const maxL = Math.max(...layer.values());
  const layers = Array.from({ length: maxL + 1 }, () => []);
  for (const n of nodes) layers[layer.get(n.id)].push(n);
  return { layers, layerOf: layer };
}

const BW = 30, GAP = 5, BOXH = 4;

function render(doc, useAscii) {
  G = useAscii ? ASC : UNI;
  const nodes = doc.nodes ?? [], flows = doc.flows ?? [];
  const boundaries = doc.trustBoundaries ?? doc.boundaries ?? [];
  const title = doc.title ?? "Data Flow Diagram";
  const head = [title, "=".repeat(Math.max(title.length, 30)),
    `Legend: [EE] entity  [P] process  [DS] store    ${G.b.repeat(3)} trust boundary    ${G.v}${G.dn} data flow`, ""];
  if (!nodes.length) return head.concat("(no nodes)").join("\n") + "\n";

  const { layers, layerOf } = assignLayers(nodes, flows);
  const widest = Math.max(...layers.map((l) => l.length * BW + (l.length - 1) * GAP), BW) + 2;

  // which band (layer li -> li+1) does each trust boundary cross? (from flows' trustBoundaryIds)
  const bndAtBand = new Map();    // band index -> boundary id
  for (const f of flows) {
    const li = layerOf.get(f.sourceId);
    if (layerOf.get(f.targetId) !== li + 1) continue;
    for (const bid of f.trustBoundaryIds ?? []) if (!bndAtBand.has(li)) bndAtBand.set(li, bid);
  }

  // geometry: x-center per node, y-top per layer (band height grows with edge count + boundary rule)
  const cx = new Map(), yTop = [];
  const bandH = layers.map((_, li) => li < layers.length - 1
    ? Math.max(2, flows.filter((f) => layerOf.get(f.sourceId) === li && layerOf.get(f.targetId) === li + 1).length + 1) + (bndAtBand.has(li) ? 1 : 0) : 0);
  let y = 0;
  layers.forEach((_, li) => { yTop[li] = y; y += BOXH + bandH[li]; });
  layers.forEach((row) => {
    const rowW = row.length * BW + (row.length - 1) * GAP;
    let x = Math.floor((widest - rowW) / 2);
    row.forEach((n) => { cx.set(n.id, x + Math.floor(BW / 2)); x += BW + GAP; });
  });

  const cv = canvas();
  // boxes
  layers.forEach((row, li) => row.forEach((n) => {
    const left = cx.get(n.id) - Math.floor(BW / 2), top = yTop[li];
    cv.text(top, left, G.tl + G.h.repeat(BW - 2) + G.tr);
    cv.text(top + 1, left, G.v + ` ${tag(n.type)}  ${trunc(n.name ?? n.id, BW - 7)}`.padEnd(BW - 1).slice(0, BW - 1) + G.v);
    cv.text(top + 2, left, G.v + ` ${n.id}`.padEnd(BW - 1).slice(0, BW - 1) + G.v);
    cv.text(top + 3, left, G.bl + G.h.repeat(BW - 2) + G.br);
  }));
  // connectors: adjacent-layer edges drawn as elbow arrows (each on its own band row)
  layers.forEach((_, li) => {
    if (li >= layers.length - 1) return;
    const edges = flows.filter((f) => layerOf.get(f.sourceId) === li && layerOf.get(f.targetId) === li + 1);
    const bandTop = yTop[li] + BOXH, tgtTop = yTop[li + 1];
    const hasBnd = bndAtBand.has(li), c0 = bandTop + (hasBnd ? 1 : 0);   // connectors start below the rule
    if (hasBnd) {                              // dashed boundary rule the arrows cross
      const bid = bndAtBand.get(li);
      for (let x = 0; x < widest; x++) cv.set(bandTop, x, G.b);
      cv.text(bandTop, 1, `${G.b}${G.b} ${bid} ${G.b}${G.b}`);
    }
    edges.forEach((f, ei) => {
      const sx = cx.get(f.sourceId), tx = cx.get(f.targetId);
      const midY = c0 + ei;                      // stagger so elbows don't overlap
      cv.vline(sx, bandTop, midY);               // drop from source box (crosses the rule)
      cv.hline(midY, sx, tx);                     // horizontal run
      cv.set(midY, sx, ei ? G.tup : G.v);
      cv.vline(tx, midY, tgtTop - 1);            // down to target box
      cv.set(tgtTop - 1, tx, G.dn);              // arrowhead
      const lbl = trunc([f.name, f.protocol].filter(Boolean).join(" / "), 38);
      if (lbl) cv.text(midY, Math.min(sx, tx) + 2, ` ${lbl} `);
    });
  });

  const out = head.concat(cv.toString(), "");
  out.push(`Trust boundaries (${boundaries.length}):`);
  out.push(...(boundaries.length ? boundaries.map((b) =>
    `  ${G.b.repeat(3)} ${b.id}: ${b.name}  [${b.outerZone ?? "?"} ${G.v} ${b.innerZone ?? "?"}]`) : ["  (none)"]));
  // edges the layered pass can't route (cross-layer, back-edges, store fan-out)
  const adj = new Set(flows.filter((f) => layerOf.get(f.targetId) === layerOf.get(f.sourceId) + 1));
  const extra = flows.filter((f) => !adj.has(f));
  if (extra.length) {
    out.push("", "Other flows (data stores / cross-layer / responses):");
    const w = Math.max(...extra.map((f) => String(f.sourceId).length));
    for (const f of extra) {
      const lbl = trunc([f.name, f.protocol, f.dataClassification].filter(Boolean).join(" / "), 44);
      const cr = f.trustBoundaryIds?.length ? `  (${f.trustBoundaryIds.join(",")})` : "";
      out.push(`  ${String(f.sourceId).padEnd(w)} ${G.h}${G.rt} ${f.targetId}   ${lbl}${cr}`);
    }
  }
  return out.join("\n") + "\n";
}

const arg = (n) => { const i = process.argv.indexOf(n); return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : null; };
const raw = arg("--in") ? readFileSync(arg("--in"), "utf8") : (() => { try { return readFileSync(0, "utf8"); } catch { return ""; } })();
if (!raw.trim()) { console.error("dfd-render: no input (--in <file.json> or stdin)"); process.exit(2); }
let doc; try { doc = JSON.parse(raw); } catch (e) { console.error("dfd-render: invalid JSON:", e.message); process.exit(2); }
const ascii = render(doc, process.argv.includes("--ascii"));
const o = arg("--out"); if (o) { mkdirSync(dirname(o), { recursive: true }); writeFileSync(o, ascii); }
process.stdout.write(ascii);
