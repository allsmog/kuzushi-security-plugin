// Attack-surface partitioning for parallel discovery.
//
// Anthropic's defending-code harness found that naively scaling discovery makes
// parallel agents "converge on the same shallow bugs." Their fix: do a first pass
// that PARTITIONS the search space (by attack surface / component / endpoint),
// then hand each partition to its own discovery agent. This module is the
// deterministic partitioner: given the entry points x-ray found (and optional
// modules from deep-context), it splits them into balanced, non-overlapping
// partitions a coordinator can fan out to parallel hunter subagents — so they
// explore different subsystems instead of racing to the same easy finding.

// Path roots that don't distinguish a subsystem — skip them to find the first
// meaningful component segment (src/auth → "auth", not "src").
const NON_DISTINGUISHING = new Set(["src", "lib", "app", "pkg", "internal", "cmd", "pkgs", "packages", "source", "main", "java", "ts", "js", "python", "go"]);

// The subsystem/component a file belongs to: the first meaningful path segment.
export function componentOf(filePath) {
  const parts = String(filePath ?? "").replace(/\\/g, "/").split("/").filter(Boolean);
  // Drop a leading "./" and any non-distinguishing roots.
  let i = 0;
  while (i < parts.length - 1 && NON_DISTINGUISHING.has(parts[i].toLowerCase())) i += 1;
  // If what's left is just the filename, the file sits at a root → group as "(root)".
  if (i >= parts.length - 1) return "(root)";
  return parts[i];
}

// Partition entry points into at most `maxPartitions` balanced groups by component.
// Returns [{ id, label, attackSurface: [...entryPoints], boundaryKinds: [...], size }].
// When there are more components than the cap, the smallest are merged into one
// "other" partition so nothing is dropped.
export function partitionAttackSurface({ entryPoints = [], maxPartitions = 6 } = {}) {
  const cap = Math.max(1, Math.min(Number(maxPartitions) || 6, 24));
  if (!entryPoints.length) return [];

  // Group by component.
  const groups = new Map();
  for (const ep of entryPoints) {
    const key = componentOf(ep.filePath);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(ep);
  }

  // Sort components by size (desc) so the cap keeps the largest attack surfaces
  // distinct and merges the long tail.
  let ranked = [...groups.entries()]
    .map(([label, members]) => ({ label, members }))
    .sort((a, b) => b.members.length - a.members.length || a.label.localeCompare(b.label));

  if (ranked.length > cap) {
    const kept = ranked.slice(0, cap - 1);
    const merged = ranked.slice(cap - 1).flatMap((g) => g.members);
    kept.push({ label: "other", members: merged });
    ranked = kept;
  }

  return ranked.map((g, i) => {
    const boundaryKinds = [...new Set(g.members.map((m) => m.kind).filter(Boolean))];
    return {
      id: `p${i + 1}`,
      label: g.label,
      size: g.members.length,
      boundaryKinds,
      // A short hint the coordinator can hand the subagent to focus its hunt.
      focusHint: boundaryKinds.length
        ? `Hunt the ${g.label} subsystem: ${boundaryKinds.slice(0, 4).join(", ")}`
        : `Hunt the ${g.label} subsystem`,
      attackSurface: g.members
    };
  });
}
