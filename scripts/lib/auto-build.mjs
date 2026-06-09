// Deep-by-default decision: should the heavy semantic indexes (CodeQL DB / Joern
// CPG) build automatically at session start?
//
// The single biggest recall lever is that interprocedural, cross-file taint only
// works with a built DB/CPG — and today those are opt-in, so the common run
// degrades to same-file tree-sitter/ripgrep linking. Making the build the DEFAULT
// (when it's a free, local operation) closes that gap without a network round
// trip. The rule: build automatically only when the engine CLI is already
// installed (so the build is local — no surprise ~1–3 GB download), source is
// present, the DB isn't built or building, and policy permits. Otherwise OFFER
// (an install needs approval) or SKIP. Pure + deterministic so the hook can't be
// surprised and the decision is testable.

// Per-profile setting, read from policy.profiles[active].analysis.autoBuildDatabases:
//   "when-installed" — build automatically iff the CLI is present (default).
//   "offer"          — never auto-build; always ask first.
//   "off"            — never build at session start (e.g. ci-locked).
const VALID_SETTINGS = new Set(["when-installed", "offer", "off"]);

export function effectiveAutoBuildSetting(policy) {
  const profile = policy?.profiles?.[policy?.activeProfile] ?? {};
  const setting = profile.analysis?.autoBuildDatabases
    ?? policy?.analysis?.autoBuildDatabases
    ?? "when-installed";
  return VALID_SETTINGS.has(setting) ? setting : "when-installed";
}

// Decide per engine. `dbBuilding` short-circuits everything (a build is already in
// flight — never double-spawn). Returns one of: "present" | "building" | "build" |
// "offer" | "skip" per engine, plus an aggregate.
export function autoBuildDecision({
  setting = "when-installed",
  sourcePresent = false,
  dbBuilding = false,
  codeqlCli = false,
  codeqlDbBuilt = false,
  joernCli = false,
  joernCpgBuilt = false
} = {}) {
  const decide = (cliPresent, built) => {
    if (built) return "present";
    if (dbBuilding) return "building";
    if (!sourcePresent) return "skip";
    if (setting === "off") return "skip";
    if (setting === "offer") return "offer";
    // "when-installed": build locally when the CLI is here; else it'd need a
    // network install, which is approval-gated — offer instead.
    return cliPresent ? "build" : "offer";
  };

  const codeql = decide(codeqlCli, codeqlDbBuilt);
  const joern = decide(joernCli, joernCpgBuilt);
  const anyBuild = codeql === "build" || joern === "build";
  const which = codeql === "build" && joern === "build" ? "both"
    : codeql === "build" ? "codeql"
    : joern === "build" ? "joern"
    : null;
  const anyOffer = codeql === "offer" || joern === "offer";

  let reason;
  if (anyBuild) reason = `engine CLI present and policy "${setting}" — building ${which} locally in the background`;
  else if (dbBuilding) reason = "a database build is already in progress";
  else if (codeql === "present" && joern === "present") reason = "CodeQL DB and Joern CPG already built";
  else if (setting === "off") reason = "policy disables session-start auto-build";
  else if (anyOffer) reason = "engine CLI not installed — an install needs approval, so offering rather than auto-building";
  else reason = "no source detected";

  return { codeql, joern, anyBuild, anyOffer, which, reason };
}
