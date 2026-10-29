// Headless-browser execution oracle for XSS verification. Isolated to the verification stage: puppeteer-core is a
// dev/verification-only dependency, imported dynamically so the core CLI never requires it, and it drives a browser
// that is already installed on the machine (no bundled download). Every page it opens is a LOCAL target URL — the
// caller builds those from the configured loopback Target, so this module never widens the host scope.
//
// Detection contract: before each navigation a fresh, isolated browser context exposes a single function on the page,
// window.__fcDetect(marker). A payload that executes calls it; the oracle records the marker it was called with. A
// fresh context per load means no window state leaks from the exploit load into the baseline load.

/** The detection global a proof payload calls when it runs: window.__fcDetect("<marker>"). */
export const DETECT_GLOBAL = "__fcDetect";

/** One page load: the URL visited, the HTTP status, and the marker a payload reported (null if none executed). */
export interface LoadResult {
  url: string;
  status: number | null;
  marker: string | null;
}

/** How to authenticate an in-browser client that keeps a bearer token client-side (e.g. a React app). */
export interface BrowserAuth {
  /** The token to install before the app loads. */
  token: string;
  /** Where the app reads it from: a localStorage/sessionStorage key, or a global assigned on window. */
  via: { kind: "localStorage" | "sessionStorage"; key: string } | { kind: "window"; path: string };
}

export interface BrowserOptions {
  /** Path to an installed Chrome/Chromium binary. Required — this module never downloads one. */
  executablePath: string;
  /** Milliseconds to wait for a navigation, and an extra settle for async handlers (onerror/onload). */
  navTimeoutMs?: number;
  settleMs?: number;
}

/** Minimal shapes of the puppeteer-core surface used here, so this file type-checks without the dependency installed. */
interface PptrPage {
  exposeFunction(name: string, fn: (value: string) => void): Promise<void>;
  evaluateOnNewDocument(fn: (arg: string) => void, arg: string): Promise<void>;
  goto(url: string, opts: { waitUntil: string; timeout: number }): Promise<{ status(): number | null } | null>;
}
interface PptrContext {
  newPage(): Promise<PptrPage>;
  close(): Promise<void>;
}
interface PptrBrowser {
  createBrowserContext(): Promise<PptrContext>;
  close(): Promise<void>;
}
interface Puppeteer {
  launch(opts: { executablePath: string; headless: boolean; args: string[] }): Promise<PptrBrowser>;
}

/** Thrown when the headless browser cannot be launched or driven (missing binary, launch failure). */
export class BrowserError extends Error {}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A launched headless browser. Each load() runs in a throwaway context, so loads never share page state. */
export class ExecBrowser {
  private constructor(
    private readonly browser: PptrBrowser,
    private readonly navTimeoutMs: number,
    private readonly settleMs: number,
    private readonly auth?: BrowserAuth,
  ) {}

  /** Launches Chrome at the given path. Dynamically imports puppeteer-core; a clear error if it is absent. */
  static async launch(opts: BrowserOptions, auth?: BrowserAuth): Promise<ExecBrowser> {
    let puppeteer: Puppeteer;
    try {
      puppeteer = ((await import("puppeteer-core")) as unknown as { default: Puppeteer }).default;
    } catch {
      throw new BrowserError(
        "XSS execution proof needs the optional 'puppeteer-core' dependency (install it with: npm i -D puppeteer-core).",
      );
    }
    let browser: PptrBrowser;
    try {
      browser = await puppeteer.launch({ executablePath: opts.executablePath, headless: true, args: ["--no-sandbox"] });
    } catch (err) {
      throw new BrowserError(`could not launch the headless browser at ${opts.executablePath}: ${(err as Error).message}`);
    }
    return new ExecBrowser(browser, opts.navTimeoutMs ?? 10000, opts.settleMs ?? 200, auth);
  }

  /**
   * Loads one URL in a fresh context and returns whether a payload executed. The URL must be local — the caller builds
   * it from the configured loopback Target. If `authenticated`, the configured client-side token is installed first.
   */
  async load(url: string, authenticated = false): Promise<LoadResult> {
    const ctx = await this.browser.createBrowserContext();
    try {
      const page = await ctx.newPage();
      let marker: string | null = null;
      await page.exposeFunction(DETECT_GLOBAL, (value: string) => {
        if (marker === null && typeof value === "string") marker = value;
      });
      if (authenticated && this.auth) await this.installToken(page, this.auth);
      let status: number | null = null;
      try {
        const res = await page.goto(url, { waitUntil: "networkidle0", timeout: this.navTimeoutMs });
        status = res?.status() ?? null;
      } catch (err) {
        throw new BrowserError(`could not load ${url}: ${(err as Error).message}`);
      }
      await sleep(this.settleMs);
      return { url, status, marker };
    } finally {
      await ctx.close();
    }
  }

  /** Installs the client-side token before any page script runs, the way the app reads it. */
  private async installToken(page: PptrPage, auth: BrowserAuth): Promise<void> {
    const via = auth.via;
    const stmt =
      via.kind === "window" ? `${via.path} = t;` : `${via.kind}.setItem(${JSON.stringify(via.key)}, t);`;
    await page.evaluateOnNewDocument(new Function("t", `try { ${stmt} } catch {}`) as (arg: string) => void, auth.token);
  }

  async close(): Promise<void> {
    try {
      await this.browser.close();
    } catch {
      /* already gone */
    }
  }
}
