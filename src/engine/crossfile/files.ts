// Project file discovery for directory scans: JS/TS sources, honoring .gitignore and skipping dependencies,
// build output and tests by default.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import ignore, { type Ignore } from "ignore";

/** Directories never scanned: dependencies, build output, caches, and test suites. */
const SKIP_DIRS = new Set([
  "node_modules",
  "bower_components",
  "vendor",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".nuxt",
  ".output",
  ".svelte-kit",
  ".turbo",
  ".cache",
  ".vercel",
  "test",
  "tests",
  "__tests__",
  "__mocks__",
  "spec",
  "e2e",
  "cypress",
]);
const SOURCE_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const SKIP_FILE = /\.(?:test|spec)\.(?:[cm]?[jt]s|[jt]sx)$|\.d\.[cm]?ts$|\.min\.js$/;

interface Matcher {
  base: string;
  ig: Ignore;
}

function gitignoreAt(dir: string): Matcher | undefined {
  const file = path.join(dir, ".gitignore");
  return existsSync(file) ? { base: dir, ig: ignore().add(readFileSync(file, "utf8")) } : undefined;
}

function isIgnored(matchers: Matcher[], abs: string, isDir: boolean): boolean {
  return matchers.some(({ base, ig }) => {
    const rel = path.relative(base, abs).split(path.sep).join("/");
    return rel !== "" && !rel.startsWith("..") && ig.ignores(isDir ? `${rel}/` : rel);
  });
}

/** .gitignore files above `root`, up to the enclosing git repository's top level. */
function ancestorMatchers(root: string): Matcher[] {
  const found: Matcher[] = [];
  for (let dir = path.dirname(root); ; dir = path.dirname(dir)) {
    const m = gitignoreAt(dir);
    if (m) found.unshift(m);
    if (existsSync(path.join(dir, ".git")) || path.dirname(dir) === dir) break;
  }
  return existsSync(path.join(root, ".git")) ? [] : found;
}

/** Absolute paths of the JS/TS source files to scan under `root`, sorted. */
export function discoverFiles(root: string): string[] {
  return walkFiles(root, (name) => SOURCE_FILE.test(name) && !SKIP_FILE.test(name));
}

/** SQL schema / migration files under `root` (same skip rules), for data-model evidence. */
export function discoverSqlFiles(root: string): string[] {
  return walkFiles(root, (name) => name.endsWith(".sql"));
}

function walkFiles(root: string, accept: (name: string) => boolean): string[] {
  const files: string[] = [];
  const walk = (dir: string, matchers: Matcher[]) => {
    const own = gitignoreAt(dir);
    const active = own ? [...matchers, own] : matchers;
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name) || isIgnored(active, abs, true)) continue;
        walk(abs, active);
      } else if (entry.isFile() && accept(entry.name) && !isIgnored(active, abs, false)) {
        files.push(abs);
      }
    }
  };
  const resolved = path.resolve(root);
  walk(resolved, ancestorMatchers(resolved));
  return files;
}
