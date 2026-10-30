// Settings layered from three sources, so a scan command can stay short: command-line flags, then MUSEFLOWCHECK_*
// environment variables, then a museflowcheck.config.json file. A flag given on the command line always wins.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export const CONFIG_FILE = "museflowcheck.config.json";

/** Keys a config file may set (as written in the JSON), each standing for the flag of the same meaning. */
const CONFIG_KEYS = {
  target: "target",
  token: "token",
  identity: "identity",
  mode: "mode",
  probeRange: "probe-range",
  loginPath: "login-path",
  loginBody: "login-body",
  tokenField: "token-field",
  browserPath: "browser-path",
  xssClient: "xss-client",
  xssTokenStore: "xss-token-store",
  startCmd: "start-cmd",
  readyPath: "ready-path",
} as const;
const FLAG_NAMES: readonly string[] = Object.values(CONFIG_KEYS);

/** The environment variable for a flag: MUSEFLOWCHECK_ plus its name in upper snake case (target → MUSEFLOWCHECK_TARGET). */
export function envVar(flag: string): string {
  return `MUSEFLOWCHECK_${flag.toUpperCase().replace(/-/g, "_")}`;
}

export class ConfigError extends Error {}

export interface LoadedConfig {
  /** The file the settings came from, when one was found. */
  file?: string;
  /** Settings by flag name, as the flag's string value. */
  values: Map<string, string>;
}

/** Reads the first config file found among `dirs` (in order); no file is an empty config. Throws ConfigError when invalid. */
export function loadConfig(dirs: string[]): LoadedConfig {
  const file = [...new Set(dirs.map((d) => path.resolve(d, CONFIG_FILE)))].find((f) => existsSync(f));
  if (!file) return { values: new Map() };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new ConfigError(`${file} is not valid JSON: ${(err as Error).message}`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ConfigError(`${file} must hold a JSON object`);
  const values = new Map<string, string>();
  for (const [key, v] of Object.entries(raw as Record<string, unknown>)) {
    if (key.startsWith("$") || key.startsWith("//")) continue; // "$schema", "//": comments in an example file
    const flag = (CONFIG_KEYS as Record<string, string>)[key];
    if (!flag) throw new ConfigError(`${file}: unknown setting "${key}" (expected one of ${Object.keys(CONFIG_KEYS).join(", ")})`);
    if (v === null || v === undefined) continue;
    if (key === "loginBody" && typeof v === "object") values.set(flag, JSON.stringify(v));
    else if (typeof v === "string" || typeof v === "number") values.set(flag, String(v));
    else throw new ConfigError(`${file}: "${key}" must be a string${key === "probeRange" ? " or number" : ""}`);
  }
  return { file, values };
}

/**
 * The value of a value-taking flag: from the command line, else its MUSEFLOWCHECK_* environment variable, else the
 * config file. Authentication is one setting: a login path given at a higher-precedence source than a token replaces
 * that token, so `--login-path` on the command line is never overridden by a token from the config file.
 */
export function layeredValues(
  flags: Map<string, string | true>,
  env: NodeJS.ProcessEnv,
  config: Map<string, string>,
): (name: string) => string | undefined {
  const fromFlag = (name: string) => (typeof flags.get(name) === "string" ? (flags.get(name) as string) : undefined);
  const layers: ((name: string) => string | undefined)[] = [
    fromFlag,
    (name) => (FLAG_NAMES.includes(name) && env[envVar(name)] ? env[envVar(name)] : undefined),
    (name) => config.get(name),
  ];
  const rank = (name: string) => layers.findIndex((layer) => layer(name) !== undefined);
  return (name) => {
    if (name === "token") {
      const [t, l] = [rank("token"), rank("login-path")];
      if (l !== -1 && (t === -1 || l < t)) return undefined;
    }
    for (const layer of layers) {
      const v = layer(name);
      if (v !== undefined) return v;
    }
    return undefined;
  };
}

/** The settings that came from the environment or the config file — names only, for a one-line note (never values). */
export function sourcedSettings(flags: Map<string, string | true>, env: NodeJS.ProcessEnv, config: Map<string, string>): { env: string[]; config: string[] } {
  const onCli = (name: string) => typeof flags.get(name) === "string";
  const fromEnv = FLAG_NAMES.filter((n) => !onCli(n) && env[envVar(n)]);
  const fromConfig = [...config.keys()].filter((n) => !onCli(n) && !fromEnv.includes(n));
  return { env: fromEnv, config: fromConfig };
}
