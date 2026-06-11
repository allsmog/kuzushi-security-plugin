#!/usr/bin/env node
// scratch-logo.mjs — standalone kuzushi banner demo. Not wired into anything.
// Run: node scratch-logo.mjs            (ember theme, default)
//      node scratch-logo.mjs steel      (cool blue->cyan theme)
// Delete me whenever; nothing imports this.

const FONT = {
  // 5 rows tall. '#' = lit pixel, ' ' = empty.
  K: ["#  #", "# # ", "##  ", "# # ", "#  #"],
  U: ["#  #", "#  #", "#  #", "#  #", " ## "],
  Z: ["####", "   #", "  # ", " #  ", "####"],
  S: ["####", "#   ", "####", "   #", "####"],
  H: ["#  #", "#  #", "####", "#  #", "#  #"],
  I: ["###", " # ", " # ", " # ", "###"],
};

const WORD = "KUZUSHI";
const GAP = 1;          // blank cols between glyphs
const SHADOW = 1;       // drop-shadow offset (cells, down+right)
const ROWS = 5;

const THEMES = {
  ember: { a: [198, 36, 36], b: [252, 196, 64], name: "ember" },   // crimson -> gold
  steel: { a: [40, 110, 210], b: [80, 230, 220], name: "steel" },  // blue   -> cyan
};
const theme = THEMES[process.argv[2]] || THEMES.ember;
const SHADOW_RGB = [44, 44, 52];

// --- lay glyphs into a sparse pixel map, track total width ---
const lit = []; // {r, c}
let cursor = 0;
for (const ch of WORD) {
  const g = FONT[ch];
  const w = Math.max(...g.map((s) => s.length));
  g.forEach((line, r) => {
    for (let c = 0; c < line.length; c++) if (line[c] === "#") lit.push({ r, c: cursor + c });
  });
  cursor += w + GAP;
}
const artW = cursor - GAP;
const W = artW + SHADOW;
const H = ROWS + SHADOW;

// --- composite buffer: shadow first, foreground on top ---
const buf = Array.from({ length: H }, () => Array(W).fill(null));
const lerp = (a, b, t) => a.map((x, i) => Math.round(x + (b[i] - x) * t));
for (const { r, c } of lit) buf[r + SHADOW][c + SHADOW] = SHADOW_RGB; // shadow
for (const { r, c } of lit) buf[r][c] = lerp(theme.a, theme.b, artW <= 1 ? 0 : c / (artW - 1)); // fg

// --- render ---
const FG = ([r, g, b]) => `\x1b[38;2;${r};${g};${b}m`;
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

let out = "\n";
for (const row of buf) {
  let line = "  ";
  let cur = null;
  for (const cell of row) {
    if (!cell) { if (cur) { line += RESET; cur = null; } line += " "; continue; }
    const key = cell.join(",");
    if (key !== cur) { line += FG(cell); cur = key; }
    line += "█";
  }
  out += line + RESET + "\n";
}

const kanji = "崩し";
const tagline = "break the balance · local-first vuln confirmation";
out += "\n  " + FG(theme.b) + kanji + RESET + DIM + "  " + tagline + RESET + "\n";
process.stdout.write(out + "\n");
