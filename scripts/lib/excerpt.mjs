// Enclosing-function excerpts. The producers historically handed the agent ±8–10
// lines around a ripgrep hit (EXCERPT_RADIUS) — too narrow to see a guard in a
// wrapper above, or logic spanning the rest of a method. This widens the window to
// the whole enclosing function/block, deterministically and without a parser
// dependency: brace-matching for C-family languages, indentation for Python/Ruby.
// The agent still has tree_sitter:node_at for an exact span when it needs one; this
// is the cheap, always-available default that lifts depth across every producer.

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

const MAX_SPAN_LINES = 400;   // cap so a pathological mega-function can't blow the prompt
const FALLBACK_RADIUS = 25;   // wider than the old ±10 when we can't find a block

const BRACE_EXT = new Set([
  ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm",
  ".java", ".kt", ".kts", ".scala", ".js", ".jsx", ".mjs", ".cjs",
  ".ts", ".tsx", ".go", ".rs", ".php", ".swift", ".cs"
]);
const INDENT_EXT = new Set([".py", ".rb"]);

function extOf(filePath) {
  const i = filePath.lastIndexOf(".");
  return i === -1 ? "" : filePath.slice(i).toLowerCase();
}

// Header heuristics — "does this line begin a function/method/block we'd want whole?"
const BRACE_HEADER = /\b(function|func|def|fn|sub)\b|\)\s*\{?\s*$|=>\s*\{?\s*$|\b(class|interface|impl|trait|struct|enum)\b|\b(if|for|while|switch|try|catch|else)\b/;
const PY_DEF = /^\s*(async\s+)?(def|class)\s/;

// Walk upward from `anchor` to the nearest plausible block header, then forward to
// the matching close brace. Returns 1-based inclusive [start,end] or null.
function braceSpan(lines, anchor) {
  let headerIdx = -1;
  for (let i = anchor; i >= 0 && anchor - i <= MAX_SPAN_LINES; i -= 1) {
    if (BRACE_HEADER.test(lines[i]) && lines.slice(i, anchor + 1).join("\n").includes("{")) {
      headerIdx = i;
      break;
    }
  }
  if (headerIdx === -1) return null;
  // Find the first '{' at or after the header, then balance braces to its match.
  let depth = 0;
  let started = false;
  let endIdx = -1;
  for (let i = headerIdx; i < lines.length && i - headerIdx <= MAX_SPAN_LINES; i += 1) {
    for (const ch of lines[i]) {
      if (ch === "{") { depth += 1; started = true; }
      else if (ch === "}") { depth -= 1; }
    }
    if (started && depth <= 0) { endIdx = i; break; }
  }
  if (endIdx === -1 || endIdx < anchor) return null;
  return [headerIdx, endIdx];
}

// Indentation-based block for Python/Ruby: climb to the nearest def/class header
// whose indent is less than the anchor's, then descend until indentation returns
// to that header level (or shallower).
function indentSpan(lines, anchor) {
  const indentOf = (s) => (s.match(/^[ \t]*/)?.[0].length ?? 0);
  // Find header at or above anchor.
  let headerIdx = -1;
  for (let i = anchor; i >= 0 && anchor - i <= MAX_SPAN_LINES; i -= 1) {
    if (PY_DEF.test(lines[i])) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return null;
  const headerIndent = indentOf(lines[headerIdx]);
  let endIdx = headerIdx;
  for (let i = headerIdx + 1; i < lines.length && i - headerIdx <= MAX_SPAN_LINES; i += 1) {
    if (lines[i].trim() === "") { endIdx = i; continue; } // blank lines belong to the block
    if (indentOf(lines[i]) <= headerIndent) break;
    endIdx = i;
  }
  return [headerIdx, endIdx];
}

// Build the excerpt as the same shape the producers already emit:
// [{ line, text }, ...] (1-based line numbers), spanning the enclosing function.
// `line` is 1-based. Falls back to ±FALLBACK_RADIUS when no block is found or the
// file/language isn't supported.
export function enclosingExcerpt(target, filePath, line) {
  const path = resolve(target, filePath);
  if (!existsSync(path) || statSync(path).isDirectory()) return null;
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const anchor0 = Math.max(0, Math.min(lines.length - 1, Number(line ?? 1) - 1));
  const ext = extOf(filePath);

  let span = null;
  if (BRACE_EXT.has(ext)) span = braceSpan(lines, anchor0);
  else if (INDENT_EXT.has(ext)) span = indentSpan(lines, anchor0);

  let start0;
  let end0;
  if (span) {
    [start0, end0] = span;
  } else {
    start0 = Math.max(0, anchor0 - FALLBACK_RADIUS);
    end0 = Math.min(lines.length - 1, anchor0 + FALLBACK_RADIUS);
  }
  // Enforce the hard cap, keeping the anchor visible.
  if (end0 - start0 + 1 > MAX_SPAN_LINES) {
    start0 = Math.max(start0, anchor0 - Math.floor(MAX_SPAN_LINES / 4));
    end0 = Math.min(lines.length - 1, start0 + MAX_SPAN_LINES - 1);
  }
  const out = [];
  for (let i = start0; i <= end0; i += 1) out.push({ line: i + 1, text: lines[i] });
  return out;
}

// Convenience for producers that key their excerpt on a known anchor line and want
// the wider window but a graceful "just the line" if reading fails.
export function excerptOrLine(target, filePath, line, text) {
  const ex = enclosingExcerpt(target, filePath, line);
  if (ex && ex.length) return ex;
  return [{ line: Number(line ?? 1), text: text ?? "" }];
}
