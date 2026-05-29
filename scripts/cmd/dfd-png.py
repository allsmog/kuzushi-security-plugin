#!/usr/bin/env python3
"""Render a DFD spec JSON to a PNG (Pillow). Standalone companion to dfd-render.mjs.

  python3 dfd-png.py --in <spec.json> --out <file.png> [--scale N]

Spec: { title, nodes:[{id,name,type,trustZone}],
        flows:[{sourceId,targetId,name?,protocol?,dataClassification?,trustBoundaryIds?}],
        trustBoundaries:[{id,name,outerZone,innerZone}] }
node.type: external_entity | process | data_store  (else => process)
"""
import argparse, json, math
from PIL import Image, ImageDraw, ImageFont

LANCZOS = getattr(getattr(Image, "Resampling", Image), "LANCZOS", 1)

# ---- type / palette -------------------------------------------------------
TYPE = {  # normalized -> (tag, shape, fill, border)
    "ee": ("EE", "rect",  (255, 232, 204), (201, 122, 24)),
    "p":  ("P",  "round", (214, 232, 255), (37, 99, 175)),
    "ds": ("DS", "store", (212, 240, 218), (32, 138, 76)),
}
def kind(t):
    t = str(t or "").lower()
    if t in ("external_entity","external","actor","entity","client","user"): return "ee"
    if t in ("data_store","datastore","database","store","file","buffer","memory"): return "ds"
    return "p"

def font(sz, bold=False):
    paths = (["/System/Library/Fonts/Supplemental/Arial Bold.ttf","/System/Library/Fonts/Helvetica.ttc",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"] if bold else
             ["/System/Library/Fonts/Supplemental/Arial.ttf","/System/Library/Fonts/Helvetica.ttc",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"])
    for p in paths:
        try: return ImageFont.truetype(p, sz)
        except Exception: pass
    return ImageFont.load_default()

def assign_layers(nodes, flows):
    ids = {n["id"] for n in nodes}
    preds = {n["id"]: 0 for n in nodes}
    for f in flows:
        if f["sourceId"] in ids and f["targetId"] in ids and f["sourceId"] != f["targetId"]:
            preds[f["targetId"]] += 1
    layer, pinned = {}, set()
    for n in nodes:
        if kind(n.get("type")) == "ee" or n.get("trustZone") == "external" or preds[n["id"]] == 0:
            layer[n["id"]] = 0; pinned.add(n["id"])
    if not pinned:
        layer[nodes[0]["id"]] = 0; pinned.add(nodes[0]["id"])
    for _ in range(len(nodes) + 2):
        changed = False
        for f in flows:
            if f["sourceId"] not in ids or f["targetId"] in pinned: continue
            ls = layer.get(f["sourceId"])
            if ls is None: continue
            if layer.get(f["targetId"], -1) < ls + 1:
                layer[f["targetId"]] = ls + 1; changed = True
        if not changed: break
    for n in nodes: layer.setdefault(n["id"], 0)
    maxL = max(layer.values())
    layers = [[] for _ in range(maxL + 1)]
    for n in nodes: layers[layer[n["id"]]].append(n)
    return layers, layer

def wrap(draw, text, fnt, maxw):
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if draw.textlength(t, font=fnt) <= maxw: cur = t
        else:
            if cur: lines.append(cur)
            cur = w
    if cur: lines.append(cur)
    return lines[:3]

def arrowhead(d, x, y, ang, col, s=9):
    d.polygon([(x, y),
               (x - s*math.cos(ang - .4), y - s*math.sin(ang - .4)),
               (x - s*math.cos(ang + .4), y - s*math.sin(ang + .4))], fill=col)

def render(doc, scale, out):
    nodes, flows = doc.get("nodes", []), doc.get("flows", [])
    bnds = doc.get("trustBoundaries", doc.get("boundaries", []))
    layers, layer_of = assign_layers(nodes, flows)
    BW, BH, GX, GY, MT, MX = 230, 78, 46, 150, 96, 50

    rows = len(layers)
    widest = max((len(r)*BW + (len(r)-1)*GX for r in layers), default=BW)
    W, H = widest + 2*MX, MT + rows*(BH+GY) + 70

    pos = {}                                   # id -> (cx, top)
    for li, row in enumerate(layers):
        roww = len(row)*BW + (len(row)-1)*GX
        x = (W - roww)//2
        for n in row:
            pos[n["id"]] = (x + BW//2, MT + li*(BH+GY)); x += BW + GX

    # which band (li -> li+1) does each boundary cross?
    band_bnd = {}
    for f in flows:
        li = layer_of[f["sourceId"]]
        if layer_of.get(f["targetId"]) == li+1:
            for bid in f.get("trustBoundaryIds", []): band_bnd.setdefault(li, bid)

    img = Image.new("RGB", (W, H), (250, 250, 248))
    d = ImageDraw.Draw(img)
    fT, fN, fI, fE, fB = font(26, True), font(15, True), font(12), font(12), font(13, True)

    d.text((MX, 26), doc.get("title", "Data Flow Diagram"), fill=(20,20,20), font=fT)

    # trust boundary dashed rules
    for li, bid in band_bnd.items():
        y = MT + li*(BH+GY) + BH + GY//2 - 18
        for x in range(MX, W-MX, 14): d.line([(x, y), (x+8, y)], fill=(200,40,40), width=2)
        nm = next((b.get("name","") for b in bnds if b.get("id")==bid), "")
        lbl = f"  {bid}: {nm}  "
        d.rectangle([MX, y-12, MX+int(d.textlength(lbl,font=fB))+6, y+10], fill=(250,250,248))
        d.text((MX+4, y-9), lbl, fill=(200,40,40), font=fB)

    # edges
    for f in flows:
        s, t = pos.get(f["sourceId"]), pos.get(f["targetId"])
        if not s or not t: continue
        cross = bool(f.get("trustBoundaryIds"))
        col = (200,40,40) if cross else (90,90,96)
        forward = layer_of[f["targetId"]] >= layer_of[f["sourceId"]]
        x1, y1 = s[0], s[1] + (BH if forward else 0)
        x2, y2 = t[0], t[1] + (0 if forward else BH)
        d.line([(x1, y1), (x2, y2)], fill=col, width=2)
        arrowhead(d, x2, y2, math.atan2(y2-y1, x2-x1), col)
        lab = " / ".join([str(x) for x in (f.get("name"), f.get("protocol")) if x])
        if lab:
            mx, my = (x1+x2)//2, (y1+y2)//2
            tw = d.textlength(lab, font=fE)
            d.rectangle([mx-tw/2-3, my-9, mx+tw/2+3, my+9], fill=(255,255,255), outline=(225,225,225))
            d.text((mx-tw/2, my-7), lab, fill=col if cross else (60,60,66), font=fE)

    # nodes (on top of edges)
    for n in nodes:
        cx, top = pos[n["id"]]; l, r = cx-BW//2, cx+BW//2; b = top+BH
        tag, shape, fill, bd = TYPE[kind(n.get("type"))]
        if shape == "round":
            d.rounded_rectangle([l, top, r, b], radius=14, fill=fill, outline=bd, width=2)
        elif shape == "store":
            d.rectangle([l, top, r, b], fill=fill, outline=fill)
            d.line([(l, top), (r, top)], fill=bd, width=2); d.line([(l, top+7),(r, top+7)], fill=bd, width=1)
            d.line([(l, b), (r, b)], fill=bd, width=2)
        else:
            d.rectangle([l, top, r, b], fill=fill, outline=bd, width=2)
        d.text((l+10, top+7), f"[{tag}]  {n['id']}", fill=bd, font=fN)
        ny = top+28
        for ln in wrap(d, n.get("name", n["id"]), fI, BW-20):
            d.text((l+10, ny), ln, fill=(30,30,34), font=fI); ny += 15

    # legend
    ly = H-34
    items = [("EE","external entity",(255,232,204),(201,122,24)),
             ("P","process",(214,232,255),(37,99,175)),
             ("DS","data store",(212,240,218),(32,138,76))]
    lx = MX
    for tg, nm, fl, bd in items:
        d.rectangle([lx, ly, lx+22, ly+16], fill=fl, outline=bd, width=2)
        d.text((lx+28, ly+1), f"{tg}  {nm}", fill=(40,40,46), font=fI)
        lx += 40 + int(d.textlength(f"{tg}  {nm}", font=fI))
    d.line([(lx, ly+8),(lx+26, ly+8)], fill=(200,40,40), width=2)
    d.text((lx+32, ly+1), "untrusted / boundary-crossing flow", fill=(200,40,40), font=fI)

    if scale != 1:
        img = img.resize((W*scale, H*scale), LANCZOS)
    img.save(out)
    print(f"wrote {out}  ({img.width}x{img.height})")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    ap.add_argument("--scale", type=int, default=2)
    a = ap.parse_args()
    with open(a.inp) as fh: doc = json.load(fh)
    render(doc, a.scale, a.out)
