#!/usr/bin/env node
// Build a prioritized, human-facing security report from .kuzushi/findings.json.
// Pure deterministic transform — no agent, no security decision. It RANKS the
// already-triaged findings (scripts/lib/risk.mjs) and RENDERS them; the verdicts
// come from the producers and the verifier. This is the "last mile" deliverable:
// the thing a maintainer or a client reads, instead of raw findings.json / SARIF.
//
// Inputs (all but findings.json are optional and read defensively):
//   findings.json   — the shared index (required)
//   chains.json     — cross-finding attack chains (/chain)
//   coverage-map.json — what /sweep actually examined (honest recall backstop)
//   code-graph.json — per-symbol caller counts → blast-radius signal for ranking
//   policy + provenance — scope/trust-plane footer
//
// Outputs: .kuzushi/report.md (always) and .kuzushi/report.html (with --html),
// rendered from one in-memory model so the two formats never disagree on content.

import { resolve, join, basename } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { storeFor, atomicWrite, emitResult, readJsonIfPresent } from "../lib/artifact-store.mjs";
import { rankFindings } from "../lib/risk.mjs";
import { loadPolicy } from "../lib/policy.mjs";
import { provenanceFor } from "../lib/provenance.mjs";

const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_TOP = 10;
const TABLE_CAP = 200; // never dump an unbounded table; note when truncated

function pluginVersion() {
  try {
    return JSON.parse(readFileSync(join(PLUGIN_ROOT, "package.json"), "utf8")).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

// ---- finding-field normalization -------------------------------------------

const norm = (p) => String(p ?? "").replace(/^\.\//, "");

function cweDisplay(cwe) {
  const c = Array.isArray(cwe) ? cwe[0] : cwe;
  if (c == null || String(c).trim() === "") return null;
  const s = String(c).trim().toUpperCase();
  if (/^CWE-\d+$/.test(s)) return s;
  if (/^\d+$/.test(s)) return `CWE-${s}`;
  return s;
}

function oneLine(text, max = 200) {
  const s = String(text ?? "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

// A finding still needs attention unless it is resolved or set aside.
function isActionable(f) {
  return !["reviewed", "noise", "remediated"].includes(f.status);
}

const SEVERITY_ICON = { critical: "⛔", high: "🔴", medium: "🟠", low: "🟡", info: "⚪", informational: "⚪", none: "⚪" };
function severityIcon(sev) { return SEVERITY_ICON[String(sev ?? "").toLowerCase()] ?? "⚪"; }
function severityWord(sev) { return String(sev ?? "medium").toLowerCase(); }
function proofBadge(proofState) { return String(proofState ?? "candidate").toUpperCase(); }

function locationsOf(f) {
  return (f.evidence ?? [])
    .filter((a) => a?.filePath)
    .map((a) => ({ path: norm(a.filePath), line: a.startLine ? Number(a.startLine) : null }));
}

function remediationFor(f) {
  if (f.exploitability?.remediation && String(f.exploitability.remediation).trim()) {
    return oneLine(f.exploitability.remediation);
  }
  if (f.fix?.patchPath) return `Patch available (${f.fix.verdict ?? "drafted"}) — ${norm(f.fix.patchPath)}`;
  if (Array.isArray(f.nextChecks) && f.nextChecks.length) return oneLine(String(f.nextChecks[0]));
  return null;
}

function artifactsFor(f) {
  const arts = [];
  if (f.poc?.proofVerdict) arts.push(`PoC ${f.poc.proofVerdict}${f.poc.harnessDir ? ` · ${norm(f.poc.harnessDir)}` : ""}`);
  if (f.fix?.patchPath) arts.push(`patch ${norm(f.fix.patchPath)} (${f.fix.verdict ?? "drafted"})`);
  if (!f.poc && f.verification?.pocReady) arts.push("PoC-ready (sketch)");
  return arts;
}

// ---- blast-radius lookup (optional, from code-graph) -----------------------
//
// code-graph.json carries per-symbol { file, line, callerCount }. For a finding,
// we take the nearest preceding symbol definition in the same file as an
// enclosing-function proxy and use its caller count as a blast-radius signal.
// Heuristic and only used when the graph exists — absence simply means 0.
function blastRadiusIndex(store) {
  const cg = readJsonIfPresent(store.codeGraphPath);
  if (!Array.isArray(cg?.symbols) || !cg.symbols.length) return null;
  const byFile = new Map();
  for (const s of cg.symbols) {
    const f = norm(s.file);
    if (!f) continue;
    if (!byFile.has(f)) byFile.set(f, []);
    byFile.get(f).push({ line: Number(s.line) || 1, callerCount: Number(s.callerCount) || 0 });
  }
  for (const arr of byFile.values()) arr.sort((a, b) => a.line - b.line);
  return byFile;
}

function makeBlastRadiusFor(byFile) {
  if (!byFile) return () => 0;
  return (finding) => {
    const ev = finding.evidence?.[0];
    if (!ev?.filePath) return 0;
    const arr = byFile.get(norm(ev.filePath));
    if (!arr?.length) return 0;
    const ln = Number(ev.startLine) || 1;
    let best = null;
    for (const s of arr) { if (s.line <= ln) best = s; else break; }
    if (best) return best.callerCount;
    return arr.reduce((m, s) => Math.max(m, s.callerCount), 0); // no def before the line → file max
  };
}

// ---- chains ----------------------------------------------------------------
//
// Assign stable display labels (C-1, C-2, …) ordered by severity so the report
// and the per-finding cross-refs agree.
const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1, informational: 1, none: 0 };
function buildChains(chainsDoc, findingByFp) {
  const chains = Array.isArray(chainsDoc?.chains) ? chainsDoc.chains : [];
  if (!chains.length) return { list: null, labelByFp: new Map() };
  const ranked = [...chains].sort((a, b) =>
    (SEVERITY_ORDER[String(b.severity ?? "").toLowerCase()] ?? 0) -
    (SEVERITY_ORDER[String(a.severity ?? "").toLowerCase()] ?? 0));
  const labelByFp = new Map();
  const list = ranked.map((c, i) => {
    const label = `C-${i + 1}`;
    const members = (c.members ?? []).filter(Boolean);
    for (const m of members) {
      if (!labelByFp.has(m)) labelByFp.set(m, []);
      labelByFp.get(m).push(label);
    }
    return {
      label,
      title: oneLine(c.title ?? c.chainId ?? label, 120),
      severity: severityWord(c.severity),
      path: c.entryPoint && c.asset ? `${oneLine(c.entryPoint, 60)} → ${oneLine(c.asset, 60)}` : null,
      memberTitles: members.map((m) => oneLine(findingByFp.get(m)?.title ?? m, 80)),
      narrative: oneLine(c.narrative ?? "", 800)
    };
  });
  return { list, labelByFp };
}

// ---- model -----------------------------------------------------------------

function decorate(entry, chainLabelByFp) {
  const f = entry.finding;
  const chainLabels = chainLabelByFp.get(f.fingerprint) ?? [];
  return {
    rank: entry.rank,
    score: entry.score,
    blastRadius: entry.blastRadius,
    fingerprint: f.fingerprint,
    title: oneLine(f.title ?? "Untitled finding", 140),
    severity: severityWord(f.severity),
    severityIcon: severityIcon(f.severity),
    cwe: cweDisplay(f.cwe),
    proofBadge: proofBadge(f.proofState),
    source: f.source ?? "unknown",
    locations: locationsOf(f),
    remediation: remediationFor(f),
    why: oneLine(f.rationale ?? "", 240),
    chainLabels,
    artifacts: artifactsFor(f)
  };
}

function postureSentence(counts) {
  if (counts.total === 0) return "No findings recorded yet — run a producer (e.g. /sweep, /threat-hunt) first.";
  if (counts.actionable === 0) return `All ${counts.total} findings are resolved or set aside — nothing outstanding to fix.`;
  const parts = [];
  if (counts.proven) parts.push(`${counts.proven} proven`);
  if (counts.confirmed) parts.push(`${counts.confirmed} confirmed`);
  if (counts.open) parts.push(`${counts.open} open`);
  const top = ["critical", "high", "medium", "low"].find((s) => counts.bySeverity[s]);
  const detail = parts.length ? ` (${parts.join(", ")})` : "";
  return `${counts.actionable} actionable finding${counts.actionable === 1 ? "" : "s"}${detail}. Highest severity present: ${top ?? "n/a"}.`;
}

function buildModel(doc, store, { all, top }) {
  const allFindings = Array.isArray(doc.findings) ? doc.findings : [];
  const findingByFp = new Map(allFindings.map((f) => [f.fingerprint, f]));

  const chainsDoc = readJsonIfPresent(store.chainsPath);
  const { list: chains, labelByFp } = buildChains(chainsDoc, findingByFp);

  const blastRadiusFor = makeBlastRadiusFor(blastRadiusIndex(store));
  const codeGraphPresent = readJsonIfPresent(store.codeGraphPath) != null;

  const scope = allFindings.filter((f) => all || isActionable(f));
  const ranked = rankFindings(scope, { blastRadiusFor }).map((e) => decorate(e, labelByFp));

  // counts (over the FULL index, regardless of --all, so the summary is honest)
  const bySeverity = {};
  const byProofState = {};
  let proven = 0, confirmed = 0, open = 0, reviewed = 0, noise = 0, remediated = 0, actionable = 0;
  for (const f of allFindings) {
    const sev = severityWord(f.severity);
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    byProofState[f.proofState] = (byProofState[f.proofState] ?? 0) + 1;
    if (f.status === "proven") proven += 1;
    else if (f.status === "confirmed") confirmed += 1;
    else if (f.status === "open") open += 1;
    if (f.status === "reviewed") reviewed += 1;
    if (f.status === "noise") noise += 1;
    if (f.status === "remediated") remediated += 1;
    if (isActionable(f)) actionable += 1;
  }
  const counts = { total: allFindings.length, actionable, bySeverity, byProofState, proven, confirmed, open };

  const coverageDoc = readJsonIfPresent(store.coverageMapPath);
  const coverage = coverageDoc ? {
    coveragePct: coverageDoc.coveragePct ?? null,
    totalFiles: coverageDoc.totalFiles ?? null,
    coveredFileCount: coverageDoc.coveredFileCount ?? null,
    uncoveredFileCount: coverageDoc.uncoveredFileCount ?? null,
    uncoveredSample: (coverageDoc.uncovered ?? []).slice(0, 25).map(norm),
    uncoveredTotal: (coverageDoc.uncovered ?? []).length
  } : null;

  let policyProfile = null;
  try { policyProfile = loadPolicy(store.target).effective?.activeProfile ?? null; } catch { policyProfile = null; }
  let provenance = null;
  try { provenance = provenanceFor(store.target); } catch { provenance = null; }

  const producers = [...new Set(allFindings.map((f) => f.source).filter(Boolean))].sort();

  const tableCapped = ranked.length > TABLE_CAP;
  return {
    meta: {
      targetName: basename(store.target) || store.target,
      target: store.target,
      pluginVersion: pluginVersion(),
      generatedAtISO: new Date().toISOString(),
      generatedDate: new Date().toISOString().slice(0, 10),
      policyProfile,
      provenance,
      producers,
      codeGraphPresent,
      boundaryNote: "Static-first local review. Exploitability verdicts are reconstructed source→sink; \"proven\" findings were triggered in an offline sandbox. Live-app / deployed-config (DAST) coverage is out of scope — see README scope & boundaries."
    },
    counts,
    posture: postureSentence(counts),
    fixFirst: ranked.slice(0, top),
    table: ranked.slice(0, TABLE_CAP),
    tableCapped,
    tableShown: Math.min(ranked.length, TABLE_CAP),
    tableTotal: ranked.length,
    chains,
    coverage,
    resolved: { reviewed, noise, remediated, total: reviewed + noise + remediated },
    includedResolved: Boolean(all)
  };
}

// ---- markdown renderer ------------------------------------------------------

function fmtLocation(loc) {
  return `${loc.path}${loc.line ? `:${loc.line}` : ""}`;
}

function renderFixFirstEntryMd(e) {
  const head = `${e.rank}. ${e.severityIcon} **${e.title}**` +
    ` — ${e.cwe ? `\`${e.cwe}\` · ` : ""}${e.proofBadge} · risk ${e.score}`;
  const meta = [];
  if (e.locations[0]) meta.push(`\`${fmtLocation(e.locations[0])}\``);
  if (e.blastRadius > 0) meta.push(`blast ${e.blastRadius}`);
  if (e.chainLabels.length) meta.push(`chain ${e.chainLabels.join(", ")}`);
  meta.push(`via /${e.source}`);
  const lines = [head, `   ${meta.join(" · ")}`];
  if (e.remediation) lines.push(`   → ${e.remediation}`);
  if (e.why) lines.push(`   _${e.why}_`);
  if (e.artifacts.length) lines.push(`   ⎯ ${e.artifacts.join(" · ")}`);
  return lines.join("\n");
}

function renderMarkdown(m) {
  const out = [];
  const c = m.counts;
  out.push(`# Security Review — ${m.meta.targetName}`);
  out.push("");
  out.push(`_kuzushi v${m.meta.pluginVersion} · ${m.meta.generatedDate} · ${c.total} finding${c.total === 1 ? "" : "s"}` +
    `${c.total ? ` (${c.proven} proven, ${c.confirmed} confirmed, ${c.open} open)` : ""}_`);
  out.push("");
  out.push(`> ${m.meta.boundaryNote}`);
  out.push("");

  out.push("## Summary");
  out.push("");
  out.push(`**${m.posture}**`);
  out.push("");
  if (c.total) {
    out.push("| Severity | Count | | Proof state | Count |");
    out.push("|---|---:|---|---|---:|");
    const sevRows = ["critical", "high", "medium", "low", "info"].filter((s) => c.bySeverity[s]);
    const proofRows = Object.entries(c.byProofState).sort((a, b) => b[1] - a[1]);
    const rows = Math.max(sevRows.length, proofRows.length);
    for (let i = 0; i < rows; i++) {
      const sev = sevRows[i] ? `${severityIcon(sevRows[i])} ${sevRows[i]}` : "";
      const sevCount = sevRows[i] ? c.bySeverity[sevRows[i]] : "";
      const ps = proofRows[i] ? proofRows[i][0] : "";
      const psCount = proofRows[i] ? proofRows[i][1] : "";
      out.push(`| ${sev} | ${sevCount} | | ${ps} | ${psCount} |`);
    }
    out.push("");
  }

  if (m.fixFirst.length) {
    out.push("## Fix first");
    out.push("");
    out.push(m.fixFirst.map(renderFixFirstEntryMd).join("\n\n"));
    out.push("");
  }

  if (m.table.length) {
    out.push(`## All ${m.includedResolved ? "" : "actionable "}findings (${m.tableTotal})`);
    out.push("");
    out.push("| # | Risk | Sev | Finding | CWE | Proof | Location | Source |");
    out.push("|---:|---:|---|---|---|---|---|---|");
    for (const e of m.table) {
      const loc = e.locations[0] ? fmtLocation(e.locations[0]) : "—";
      out.push(`| ${e.rank} | ${e.score} | ${e.severityIcon} ${e.severity} | ${mdCell(e.title)} | ${e.cwe ?? "—"} | ${e.proofBadge} | \`${loc}\` | ${e.source} |`);
    }
    if (m.tableCapped) out.push(`\n_Showing top ${m.tableShown} of ${m.tableTotal} by risk._`);
    out.push("");
  }

  if (m.chains) {
    out.push(`## Attack chains (${m.chains.length})`);
    out.push("");
    for (const ch of m.chains) {
      out.push(`### ${ch.label} · ${ch.title} (${ch.severity})`);
      if (ch.path) out.push(`Path: \`${ch.path}\``);
      out.push(`Members: ${ch.memberTitles.join(" → ")}`);
      if (ch.narrative) { out.push(""); out.push(ch.narrative); }
      out.push("");
    }
  }

  if (m.coverage) {
    out.push("## Coverage");
    out.push("");
    const cov = m.coverage;
    const pct = cov.coveragePct != null ? `${cov.coveragePct}% of files` : "coverage recorded";
    out.push(`${pct}` +
      (cov.coveredFileCount != null && cov.totalFiles != null ? ` · ${cov.coveredFileCount}/${cov.totalFiles} files examined` : "") +
      (cov.uncoveredTotal ? ` · ${cov.uncoveredTotal} uncovered` : ""));
    if (cov.uncoveredSample.length) {
      out.push("");
      out.push("Uncovered (sample):");
      for (const u of cov.uncoveredSample) out.push(`- \`${u}\``);
      if (cov.uncoveredTotal > cov.uncoveredSample.length) out.push(`- … and ${cov.uncoveredTotal - cov.uncoveredSample.length} more`);
    }
    out.push("");
  }

  out.push("## Scope & provenance");
  out.push("");
  if (m.meta.policyProfile) out.push(`- Policy profile: \`${m.meta.policyProfile}\``);
  if (m.meta.producers.length) out.push(`- Producers run: ${m.meta.producers.map((p) => `/${p}`).join(", ")}`);
  if (m.meta.provenance?.toolchainDigest) out.push(`- Toolchain digest: \`${m.meta.provenance.toolchainDigest}\``);
  if (!m.meta.codeGraphPresent) out.push("- Blast-radius unavailable (no code-graph — run `/code-graph` to enable caller-count ranking).");
  if (m.resolved.total) {
    out.push(`- Resolved / set aside (not shown above): ${m.resolved.reviewed} reviewed, ${m.resolved.noise} noise, ${m.resolved.remediated} remediated` +
      (m.includedResolved ? "" : " — run `/report all` to include them."));
  }
  out.push("");
  out.push(`_Generated by kuzushi-security-plugin v${m.meta.pluginVersion} at ${m.meta.generatedAtISO}. Findings are evidence-anchored; see \`.kuzushi/findings.json\` for the full record._`);
  out.push("");
  return out.join("\n");
}

// Escape a markdown table cell: pipes and newlines would break the row.
function mdCell(text) {
  return String(text ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

// ---- html renderer ----------------------------------------------------------

function esc(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(m) {
  const c = m.counts;
  const sevClass = (s) => `sev-${s}`;
  const fixCards = m.fixFirst.map((e) => {
    const meta = [];
    if (e.locations[0]) meta.push(`<code>${esc(fmtLocation(e.locations[0]))}</code>`);
    if (e.blastRadius > 0) meta.push(`blast ${e.blastRadius}`);
    if (e.chainLabels.length) meta.push(`chain ${esc(e.chainLabels.join(", "))}`);
    meta.push(`via /${esc(e.source)}`);
    return `<div class="card ${sevClass(e.severity)}">
      <div class="card-head"><span class="rank">#${e.rank}</span>
        <span class="title">${esc(e.title)}</span>
        <span class="badges">${e.cwe ? `<span class="cwe">${esc(e.cwe)}</span>` : ""}<span class="proof">${esc(e.proofBadge)}</span><span class="risk">risk ${e.score}</span></span>
      </div>
      <div class="meta">${meta.join(" · ")}</div>
      ${e.remediation ? `<div class="rem">→ ${esc(e.remediation)}</div>` : ""}
      ${e.why ? `<div class="why">${esc(e.why)}</div>` : ""}
      ${e.artifacts.length ? `<div class="arts">${esc(e.artifacts.join(" · "))}</div>` : ""}
    </div>`;
  }).join("\n");

  const tableRows = m.table.map((e) =>
    `<tr class="${sevClass(e.severity)}"><td>${e.rank}</td><td>${e.score}</td><td>${esc(e.severity)}</td><td>${esc(e.title)}</td><td>${esc(e.cwe ?? "—")}</td><td>${esc(e.proofBadge)}</td><td><code>${esc(e.locations[0] ? fmtLocation(e.locations[0]) : "—")}</code></td><td>${esc(e.source)}</td></tr>`
  ).join("\n");

  const chainsHtml = m.chains ? `<section><h2>Attack chains (${m.chains.length})</h2>${m.chains.map((ch) =>
    `<div class="chain ${sevClass(ch.severity)}"><h3>${esc(ch.label)} · ${esc(ch.title)} <small>(${esc(ch.severity)})</small></h3>
      ${ch.path ? `<div class="path"><code>${esc(ch.path)}</code></div>` : ""}
      <div class="members">${esc(ch.memberTitles.join(" → "))}</div>
      ${ch.narrative ? `<p>${esc(ch.narrative)}</p>` : ""}</div>`).join("\n")}</section>` : "";

  const coverageHtml = m.coverage ? `<section><h2>Coverage</h2><p>${m.coverage.coveragePct != null ? `${m.coverage.coveragePct}% of files` : "coverage recorded"}${m.coverage.coveredFileCount != null && m.coverage.totalFiles != null ? ` · ${m.coverage.coveredFileCount}/${m.coverage.totalFiles} files examined` : ""}${m.coverage.uncoveredTotal ? ` · ${m.coverage.uncoveredTotal} uncovered` : ""}</p>${m.coverage.uncoveredSample.length ? `<ul class="uncovered">${m.coverage.uncoveredSample.map((u) => `<li><code>${esc(u)}</code></li>`).join("")}${m.coverage.uncoveredTotal > m.coverage.uncoveredSample.length ? `<li>… and ${m.coverage.uncoveredTotal - m.coverage.uncoveredSample.length} more</li>` : ""}</ul>` : ""}</section>` : "";

  const sevCounts = ["critical", "high", "medium", "low", "info"].filter((s) => c.bySeverity[s])
    .map((s) => `<span class="chip ${sevClass(s)}">${s}: ${c.bySeverity[s]}</span>`).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Review — ${esc(m.meta.targetName)}</title>
<style>
:root{--bg:#0f1117;--fg:#e6e8ee;--muted:#9aa3b2;--card:#171a23;--line:#262b38;--crit:#ff4d4f;--high:#ff7a45;--med:#faad14;--low:#52c41a;--info:#8c8c8c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:15px;margin:18px 0 6px}
.sub{color:var(--muted);font-size:13px}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:#0b0d13;padding:1px 5px;border-radius:4px;color:#c9d1e8}
blockquote{margin:16px 0;padding:10px 14px;border-left:3px solid var(--line);color:var(--muted);font-size:13px}
.posture{font-weight:600;font-size:16px;margin:8px 0 16px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.chip{font-size:12px;padding:2px 9px;border-radius:999px;border:1px solid var(--line)}
.card{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:12px 14px;margin:10px 0}
.card-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}.rank{color:var(--muted);font-variant-numeric:tabular-nums}.title{font-weight:600;flex:1 1 auto}
.badges{display:flex;gap:6px;align-items:center}.badges span{font-size:11px;padding:1px 7px;border-radius:4px;border:1px solid var(--line);color:var(--muted)}
.badges .risk{color:var(--fg)}.meta{color:var(--muted);font-size:12.5px;margin-top:6px}.rem{margin-top:6px}.why{color:var(--muted);font-size:13px;font-style:italic;margin-top:4px}.arts{color:var(--muted);font-size:12px;margin-top:6px}
.sev-critical{border-left-color:var(--crit)}.sev-high{border-left-color:var(--high)}.sev-medium{border-left-color:var(--med)}.sev-low{border-left-color:var(--low)}.sev-info{border-left-color:var(--info)}
.chip.sev-critical{color:var(--crit)}.chip.sev-high{color:var(--high)}.chip.sev-medium{color:var(--med)}.chip.sev-low{color:var(--low)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
td:first-child,td:nth-child(2){text-align:right;font-variant-numeric:tabular-nums}
.chain{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:10px 14px;margin:10px 0}.members{color:var(--muted);font-size:13px}
ul.uncovered{columns:2;font-size:13px;color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
</style></head>
<body><div class="wrap">
<h1>Security Review — ${esc(m.meta.targetName)}</h1>
<div class="sub">kuzushi v${esc(m.meta.pluginVersion)} · ${esc(m.meta.generatedDate)} · ${c.total} finding${c.total === 1 ? "" : "s"}${c.total ? ` (${c.proven} proven, ${c.confirmed} confirmed, ${c.open} open)` : ""}</div>
<blockquote>${esc(m.meta.boundaryNote)}</blockquote>
<section><h2>Summary</h2><div class="posture">${esc(m.posture)}</div><div class="chips">${sevCounts}</div></section>
${m.fixFirst.length ? `<section><h2>Fix first</h2>${fixCards}</section>` : ""}
${m.table.length ? `<section><h2>All ${m.includedResolved ? "" : "actionable "}findings (${m.tableTotal})</h2>
<table><thead><tr><th>#</th><th>Risk</th><th>Sev</th><th>Finding</th><th>CWE</th><th>Proof</th><th>Location</th><th>Source</th></tr></thead>
<tbody>${tableRows}</tbody></table>${m.tableCapped ? `<p class="sub">Showing top ${m.tableShown} of ${m.tableTotal} by risk.</p>` : ""}</section>` : ""}
${chainsHtml}
${coverageHtml}
<footer>${m.meta.policyProfile ? `Policy profile: <code>${esc(m.meta.policyProfile)}</code> · ` : ""}${m.meta.producers.length ? `Producers: ${esc(m.meta.producers.map((p) => "/" + p).join(", "))} · ` : ""}${m.resolved.total ? `${m.resolved.total} resolved/set-aside ${m.includedResolved ? "(included)" : "(hidden; pass all)"} · ` : ""}Generated ${esc(m.meta.generatedAtISO)}. Full record: <code>.kuzushi/findings.json</code>.</footer>
</div></body></html>
`;
}

// ---- entry point ------------------------------------------------------------

export function buildReport(target, { all = false, top = DEFAULT_TOP, html = false } = {}) {
  const resolvedTarget = resolve(target);
  const store = storeFor(resolvedTarget);
  const doc = readJsonIfPresent(store.findingsPath);
  if (!doc) throw new Error(`${store.findingsPath} not found — run a producer (e.g. /sweep, /threat-hunt) first`);

  const model = buildModel(doc, store, { all, top: Math.max(1, Number(top) || DEFAULT_TOP) });
  const markdown = renderMarkdown(model);
  const reportPath = join(store.root, "report.md");
  atomicWrite(reportPath, markdown.endsWith("\n") ? markdown : `${markdown}\n`);

  let htmlPath = null;
  if (html) {
    htmlPath = join(store.root, "report.html");
    atomicWrite(htmlPath, renderHtml(model));
  }

  return {
    ok: true,
    status: "completed",
    target: resolvedTarget,
    reportPath,
    htmlPath,
    findingCount: model.counts.total,
    actionableCount: model.counts.actionable,
    fixFirstCount: model.fixFirst.length,
    chainCount: model.chains?.length ?? 0,
    includedResolved: Boolean(all)
  };
}

function main() {
  if (process.argv.includes("--help")) {
    console.log("report-build --target <path> [--all] [--html] [--top <n>]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help", "all", "html"], value: ["target", "top"] });
  if (!flags.target) {
    console.error("report-build: --target is required");
    process.exit(1);
  }
  emitResult(buildReport(flags.target, { all: Boolean(flags.all), html: Boolean(flags.html), top: flags.top }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
