#!/usr/bin/env node
// Framework-owned prototype-pollution oracle (CWE-1321) — the invariant-oracle analog of the
// sanitizer for the memory class. Prototype pollution emits NO crash, so a sanitizer never sees
// it; the oracle is instead a post-condition INVARIANT: after driving the target with a payload
// that names a dangerous key (__proto__ / constructor.prototype), did a fresh object / the global
// Object.prototype gain a property it must never have?
//
// CRITICAL (determinism boundary): the discovery agent only DECLARES the target module + input
// shape — it writes NO code that runs here. This script (framework-owned) supplies the payloads,
// drives them, and checks the prototype, so the verdict is ungameable: the marker only fires if
// the prototype is ACTUALLY polluted. The finalize trusts the marker exactly as it trusts a
// sanitizer report.
//
// Usage: node proto-pollution.mjs <absoluteTargetModule> <inputShape>
//   inputShape ∈ argv-array | merge-object | json-parse | query-string | auto

import { createRequire } from "node:module";

const SENTINEL = "kuzushiPolluted_marker";
const [, , targetModule, inputShapeArg = "auto"] = process.argv;
if (!targetModule) { console.error("proto-oracle: <targetModule> required"); process.exit(2); }

const PAYLOADS = {
  "argv-array": [[`--__proto__.${SENTINEL}=polluted`], [`--constructor.prototype.${SENTINEL}=polluted`]],
  "merge-object": [JSON.parse(`{"__proto__":{"${SENTINEL}":"polluted"}}`), JSON.parse(`{"constructor":{"prototype":{"${SENTINEL}":"polluted"}}}`)],
  "json-parse": [`{"__proto__":{"${SENTINEL}":"polluted"}}`, `{"constructor":{"prototype":{"${SENTINEL}":"polluted"}}}`],
  "query-string": [`__proto__[${SENTINEL}]=polluted`, `constructor[prototype][${SENTINEL}]=polluted`]
};

const require = createRequire(`${process.cwd()}/`);
let target;
try { target = require(require.resolve(targetModule, { paths: [process.cwd(), targetModule] })); }
catch (e) { console.error("proto-oracle: cannot load target:", e?.message ?? e); process.exit(2); }

// Resolve a callable from the export (a bare function, .default, or a common parse-ish method).
const callable = typeof target === "function" ? target
  : typeof target?.default === "function" ? target.default
  : typeof target?.parse === "function" ? target.parse
  : typeof target?.merge === "function" ? target.merge
  : typeof target?.set === "function" ? target.set
  : null;
if (!callable) { console.error("proto-oracle: target export is not callable"); process.exit(2); }

const shapes = inputShapeArg === "auto" ? Object.keys(PAYLOADS) : [inputShapeArg];
for (const shape of shapes) {
  for (const payload of PAYLOADS[shape] ?? []) {
    delete Object.prototype[SENTINEL];                 // clean slate per vector
    try { callable(payload); } catch { /* a throw is fine — we only care about the side effect */ }
    const fresh = {};
    if (fresh[SENTINEL] !== undefined || Object.prototype[SENTINEL] !== undefined) {
      // The proof: a property leaked onto the prototype chain of an object that never set it.
      console.log(`KUZUSHI-ORACLE: CWE-1321 prototype-pollution via ${shape} (sentinel ${SENTINEL} reached Object.prototype)`);
      delete Object.prototype[SENTINEL];
      process.exit(66);
    }
  }
}
console.log("proto-oracle: clean — no prototype pollution observed");
process.exit(0);
