// Argument parsing for plugin-owned scripts.
//
// Usage:
//   import { parseFlags } from "./lib/argv.mjs";
//   const { flags, repeat, positionals } = parseFlags(process.argv.slice(2), {
//     boolean: ["json", "plain", "dry-run", "help"],
//     value:   ["target", "input", "input-file", "mode", "run-id", "limit"],
//     repeat:  ["option"]
//   });
//
// Unknown flags throw. `--key=value` and `--key value` both work. Values that
// look like `--something` are treated as values when consumed by a known
// value-flag (so `--reason --foo` would assign `--foo` to `--reason`); callers
// shouldn't rely on that shape, but the contract is strict otherwise.

export function parseFlags(argv, spec = {}) {
  const booleanSet = new Set(spec.boolean ?? []);
  const valueSet = new Set(spec.value ?? []);
  const repeatSet = new Set(spec.repeat ?? []);
  const flags = {};
  const repeat = new Map();
  const positionals = [];

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--") {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const raw = token.slice(2);
    const eqIndex = raw.indexOf("=");
    const key = eqIndex === -1 ? raw : raw.slice(0, eqIndex);
    const inlineValue = eqIndex === -1 ? undefined : raw.slice(eqIndex + 1);

    if (booleanSet.has(key)) {
      flags[key] = inlineValue === undefined ? true : inlineValue !== "false";
      continue;
    }
    if (repeatSet.has(key)) {
      const value = inlineValue ?? argv[++i];
      if (value === undefined) {
        throw new Error(`Missing value for --${key}`);
      }
      const list = repeat.get(key) ?? [];
      list.push(value);
      repeat.set(key, list);
      continue;
    }
    if (valueSet.has(key)) {
      const value = inlineValue ?? argv[++i];
      if (value === undefined) {
        throw new Error(`Missing value for --${key}`);
      }
      flags[key] = value;
      continue;
    }
    throw new Error(`Unknown flag --${key}`);
  }

  return { flags, repeat, positionals };
}

// Convenience: load --input <json> | --input-file <path> into a parsed object.
// If neither is provided, returns {}. Caller passes the flags object from
// parseFlags(). Throws on malformed JSON or missing file.
export function loadInput(flags, fs = null) {
  if (flags["input-file"]) {
    const reader = fs ?? require("node:fs");
    const text = typeof reader.readFileSync === "function"
      ? reader.readFileSync(flags["input-file"], "utf8")
      : null;
    if (text === null) throw new Error("loadInput: filesystem reader unavailable");
    return text.trim() ? JSON.parse(text) : {};
  }
  if (flags.input === undefined || flags.input === null || flags.input === "") return {};
  if (typeof flags.input === "object") return flags.input;
  return JSON.parse(flags.input);
}
