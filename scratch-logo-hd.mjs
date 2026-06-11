#!/usr/bin/env node
// scratch-logo-hd.mjs — crisp half-block kuzushi banner. Standalone, wired into nothing.
// Each terminal cell carries 2 stacked pixels (▀ = fg top / bg bottom), so the
// 7px-tall font renders in ~4 rows at double vertical resolution.
// Run: node scratch-logo-hd.mjs [ember|steel]

const FONT = { // 7 rows tall, width 5
  K: ["#   #","#  # ","# #  ","##   ","# #  ","#  # ","#   #"],
  U: ["#   #","#   #","#   #","#   #","#   #","#   #"," ### "],
  Z: ["#####","    #","   # ","  #  "," #   ","#    ","#####"],
  S: ["#####","#    ","#    ","#####","    #","    #","#####"],
  H: ["#   #","#   #","#   #","#####","#   #","#   #","#   #"],
  I: ["#####","  #  ","  #  ","  #  ","  #  ","  #  ","#####"],
};
const WORD = "KUZUSHI", GAP = 1, SHADOW = 1, ROWS = 7;

const THEMES = {
  ember: { a: [198, 36, 36], b: [252, 196, 64] },
  steel: { a: [40, 110, 210], b: [80, 230, 220] },
};
const theme = THEMES[process.argv[2]] || THEMES.ember;
const SHADOW_RGB = [40, 40, 48];

// lay glyphs into a sparse pixel list
const lit = [];
let cursor = 0;
for (const ch of WORD) {
  const g = FONT[ch], w = 5;
  g.forEach((line, r) => { for (let c = 0; c < line.length; c++) if (line[c] === "#") lit.push([r, cursor + c]); });
  cursor += w + GAP;
}
const artW = cursor - GAP, W = artW + SHADOW, H = ROWS + SHADOW;

// composite: shadow under, gradient over
const buf = Array.from({ length: H }, () => Array(W).fill(null));
const lerp = (a, b, t) => a.map((x, i) => Math.round(x + (b[i] - x) * t));
for (const [r, c] of lit) buf[r + SHADOW][c + SHADOW] = SHADOW_RGB;
for (const [r, c] of lit) buf[r][c] = lerp(theme.a, theme.b, artW <= 1 ? 0 : c / (artW - 1));

// half-block render: pair rows (top,bottom) -> one cell
const FG = ([r, g, b]) => `\x1b[38;2;${r};${g};${b}m`;
const BG = ([r, g, b]) => `\x1b[48;2;${r};${g};${b}m`;
const R = "\x1b[0m";

let out = "\n";
for (let r = 0; r < H; r += 2) {
  let line = "  ";
  for (let c = 0; c < W; c++) {
    const top = buf[r][c], bot = (buf[r + 1] || [])[c];
    if (!top && !bot) { line += " "; }
    else if (top && !bot) { line += FG(top) + "▀" + R; }
    else if (!top && bot) { line += FG(bot) + "▄" + R; }
    else { line += FG(top) + BG(bot) + "▀" + R; }
  }
  out += line + "\n";
}
out += "\n  " + FG(theme.b) + "崩し" + R + "\x1b[2m  break the balance · local-first vuln confirmation" + R + "\n";
process.stdout.write(out + "\n");
