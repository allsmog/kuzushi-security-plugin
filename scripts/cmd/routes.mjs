#!/usr/bin/env node
// Framework-aware route / endpoint enumeration. Parses Express/Flask/FastAPI/Django/
// Spring/Rails/Go route declarations and OpenAPI/Swagger specs into structured entry
// points { framework, method, routePath, filePath, line } — the attacker-reachable
// surface that generic entry-point regexes miss. Feeds /deep-hunt anchoring and
// risk-ranking; also runnable standalone to inventory a service's endpoints.

import { resolve } from "node:path";
import { parseFlags } from "../lib/argv.mjs";
import { emitResult } from "../lib/artifact-store.mjs";
import { extractRoutes } from "../lib/routes.mjs";

function main() {
  if (process.argv.includes("--help")) {
    console.log("routes --target <path> [--scope <dir>] [--cap <n>]");
    process.exit(0);
  }
  const { flags } = parseFlags(process.argv.slice(2), { boolean: ["help"], value: ["target", "scope", "cap"] });
  if (!flags.target) { console.error("routes: --target is required"); process.exit(1); }
  const target = resolve(flags.target);
  const routes = extractRoutes(target, { scopeDir: flags.scope ?? ".", cap: Number(flags.cap) || 300 });
  const byFramework = routes.reduce((acc, r) => { acc[r.framework] = (acc[r.framework] ?? 0) + 1; return acc; }, {});
  emitResult({ ok: true, target, routeCount: routes.length, byFramework, routes });
}

main();
