// Deterministic per-CWE remediation guidance.
//
// Only /mem-exploitability attached remediation before; the producers that promote
// the bulk of findings (threat-hunt, systems-hunt, taint-analysis) left the "now
// what?" unanswered. A finding the user can't act on is half a finding. This maps
// the common CWE classes to a concrete, one-line fix so every promoted finding
// carries baseline guidance — the agent's own remediation always wins when given;
// this is the floor, computed host-side so it can't be skipped.

// Keyed by CWE number (string). Concise, imperative, class-level fixes — not a
// spec dump. The agent refines per-site; this guarantees a non-empty floor.
const BY_CWE = {
  "22": "Resolve the path and confirm it stays within the intended base directory (realpath + prefix check); reject `..`, absolute paths, and symlinks. Prefer an allowlist of known filenames.",
  "73": "Don't let untrusted input choose the file path; map it to an internal id/allowlist and canonicalize before use.",
  "77": "Avoid the shell: pass arguments as an array to execFile/spawn (no `sh -c`). If a shell is unavoidable, allowlist and escape every argument.",
  "78": "Avoid the shell: use execFile/spawn with an argument array instead of a shell string. Allowlist the command and validate each argument.",
  "79": "Context-encode output (HTML/attribute/JS/URL) at the sink, prefer a framework auto-escaping template, and set a restrictive CSP. Never mark untrusted data as safe/raw.",
  "89": "Use parameterized queries / prepared statements (bind variables); never concatenate input into SQL. For dynamic identifiers, map through an allowlist.",
  "90": "Escape LDAP special characters per RFC 4515 (or use a parameterized LDAP API); validate the DN/filter against an allowlist.",
  "94": "Don't evaluate untrusted input as code (no eval/Function/dynamic require with user data). Replace with a data-driven dispatch table or a safe parser.",
  "95": "Remove the dynamic eval of user input; use a sandboxed interpreter or a fixed operation set instead.",
  "113": "Strip CR/LF from any user value placed in a header; use the framework's header API which rejects control characters.",
  "117": "Neutralize newlines/control chars before logging untrusted input (or use structured logging) so an attacker can't forge log entries.",
  "190": "Use checked/wider arithmetic or explicit bounds checks before allocations and index math; reject sizes that can overflow.",
  "287": "Enforce authentication on every protected path; use a vetted auth library, constant-time secret comparison, and fail closed.",
  "326": "Replace the weak algorithm/key size with a current standard (e.g. AES-256-GCM, RSA-3072/ECDSA-P256, Argon2/bcrypt for passwords).",
  "327": "Replace the broken primitive (MD5/SHA-1/DES/ECB) with a vetted modern one and an authenticated mode; don't roll your own crypto.",
  "346": "Validate the Origin/Referer (or a signed token) against an allowlist; don't trust attacker-supplied origin headers.",
  "352": "Require an anti-CSRF token (or SameSite=strict cookies) on every state-changing request and verify it server-side.",
  "362": "Serialize the read-modify-write with a lock/transaction or an atomic compare-and-swap; don't assume single-threaded ordering.",
  "367": "Eliminate the check-then-use gap: operate on a handle/transaction so the resource can't change between the check and the act (TOCTOU).",
  "400": "Bound the work: cap input size, request rate, recursion depth, and concurrency; stream instead of buffering unbounded input.",
  "434": "Validate upload type by content (not extension), store outside the web root with a generated name, and never execute uploads.",
  "502": "Don't deserialize untrusted data with a code-capable deserializer; use a data-only format (JSON) with a strict schema, or an allowlist of types.",
  "601": "Validate redirect targets against an allowlist of internal paths/hosts; don't redirect to a raw user-supplied URL.",
  "611": "Disable external entities and DTDs in the XML parser (XXE-safe configuration) before parsing untrusted XML.",
  "639": "Enforce object-level authorization: check the current user owns/may access the object by id on every request, server-side.",
  "776": "Cap entity expansion / disable DTDs to prevent billion-laughs; use a hardened parser configuration.",
  "798": "Remove the hardcoded secret; load it from a secrets manager / environment and rotate the exposed value.",
  "829": "Pin and integrity-check dependencies (lockfile + hashes); vet the source before including externally-controlled functionality.",
  "862": "Add an authorization check on the handler (deny by default); verify the caller's role/permission for this action server-side.",
  "863": "Fix the authorization logic so it checks the right subject/role/resource; deny by default and test the negative case.",
  "915": "Bind only an allowlist of fields from user input; never mass-assign attacker-controlled keys onto trusted objects.",
  "918": "Validate the request target against an allowlist of hosts/schemes, resolve and re-check the IP (block private/link-local/metadata), and disable redirects to untrusted hosts.",
  "943": "Use a parameterized query API and reject operator objects (e.g. `$where`, `$ne`) from user input; validate types server-side.",
  "1321": "Reject `__proto__`/`constructor`/`prototype` keys when merging or setting properties from untrusted input; use a null-prototype map.",
  "1333": "Bound or replace the user-controlled regex (avoid catastrophic backtracking); use a linear-time engine or a timeout.",
  "1336": "Never render user input as a template; pass it as data to a sandboxed engine with auto-escaping."
};

const GENERIC = "Treat the input as untrusted: validate/normalize at the boundary, neutralize it for the specific sink (escape/parameterize/encode), and enforce authorization. Add a regression test for the trigger.";

// Normalize "CWE-78", "cwe_078", 78 → "78".
function cweNumber(cwe) {
  if (cwe == null) return null;
  const first = Array.isArray(cwe) ? cwe[0] : cwe;
  const m = String(first).match(/\d+/);
  return m ? String(parseInt(m[0], 10)) : null;
}

// Class-level remediation for a CWE, or a sane generic floor. Never empty.
export function remediationFor(cwe) {
  const n = cweNumber(cwe);
  return (n && BY_CWE[n]) || GENERIC;
}

export const _internals = { BY_CWE, GENERIC, cweNumber };
