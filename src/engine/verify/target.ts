// Verification target configuration and the hard local-only guard.
//
// SAFETY: verification sends real HTTP requests that exercise a vulnerability, so it is allowed to run ONLY against
// a loopback target the user configured explicitly. The guard below is the single chokepoint: every request in this
// stage goes through a Target built here, and Target construction throws unless the host is loopback. There is no
// host discovery and no fallback — without a configured target, the verify stage never runs at all.

/** A fetch-compatible function, injectable so the stage can be tested without a network. */
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class TargetError extends Error {}

/** Hostnames that resolve to this machine's loopback interface, and the reserved local TLDs. */
function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]") return true;
  return h.endsWith(".localhost") || h.endsWith(".test");
}

/** Throws unless `url` is a well-formed http(s) URL whose host is loopback. Returns the normalized origin+path. */
export function assertLocalTarget(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TargetError(`--target must be a full URL (e.g. http://localhost:4000), got ${JSON.stringify(url)}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TargetError(`--target must be http(s), got ${parsed.protocol}`);
  }
  if (!isLoopbackHost(parsed.hostname)) {
    throw new TargetError(
      `refusing to verify against non-local host ${JSON.stringify(parsed.hostname)}. ` +
        `Verification only runs against a loopback target you run yourself (localhost, 127.0.0.1, ::1, *.localhost, *.test).`,
    );
  }
  return parsed.origin + parsed.pathname.replace(/\/$/, "");
}

/** How the PoC requests authenticate: a bearer token, or credentials the tool posts to a local login route for one. */
export type AuthConfig =
  | { kind: "none" }
  | { kind: "token"; token: string }
  | { kind: "login"; path: string; body: Record<string, unknown>; tokenField: string };

export interface TargetOptions {
  url: string;
  auth?: AuthConfig;
  fetch?: FetchLike;
}

/** A configured, validated local target. Every verification request is sent through one instance. */
export class Target {
  readonly base: string;
  private readonly fetchImpl: FetchLike;
  private readonly auth: AuthConfig;
  private bearer?: string;

  constructor(opts: TargetOptions) {
    this.base = assertLocalTarget(opts.url);
    this.auth = opts.auth ?? { kind: "none" };
    this.fetchImpl = opts.fetch ?? ((url, init) => fetch(url, init));
    if (this.auth.kind === "token") this.bearer = this.auth.token;
  }

  /** Resolves the bearer token, exchanging login credentials for one on first use. */
  private async token(): Promise<string | undefined> {
    if (this.bearer !== undefined || this.auth.kind !== "login") return this.bearer;
    const res = await this.send("POST", this.auth.path, { body: this.auth.body });
    let payload: unknown;
    try {
      payload = JSON.parse(res.body);
    } catch {
      throw new TargetError(`login to ${this.auth.path} did not return JSON (status ${res.status})`);
    }
    const token = (payload as Record<string, unknown>)?.[this.auth.tokenField];
    if (typeof token !== "string" || token === "") {
      throw new TargetError(`login response had no string field ${JSON.stringify(this.auth.tokenField)}`);
    }
    this.bearer = token;
    return token;
  }

  /** Sends one request to the target. `authenticated` adds the bearer token (default true). */
  async request(method: string, path: string, init: { query?: Record<string, string>; body?: unknown; authenticated?: boolean } = {}) {
    const headers: Record<string, string> = {};
    if (init.authenticated !== false) {
      const token = await this.token();
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    return this.send(method, path, { query: init.query, body: init.body, headers });
  }

  private async send(method: string, path: string, init: { query?: Record<string, string>; body?: unknown; headers?: Record<string, string> }) {
    const url = new URL(this.base + (path.startsWith("/") ? path : `/${path}`));
    for (const [k, v] of Object.entries(init.query ?? {})) url.searchParams.set(k, v);
    assertLocalTarget(url.toString()); // defense in depth: a crafted path cannot redirect us off-host
    const headers = { ...init.headers };
    let body: string | undefined;
    // GET/HEAD cannot carry a body (fetch throws); ignore one if the PoC supplied it, and put it in the query instead.
    const canHaveBody = method !== "GET" && method !== "HEAD";
    if (init.body !== undefined && canHaveBody) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.body);
    } else if (init.body !== undefined && init.body !== null && typeof init.body === "object") {
      for (const [k, v] of Object.entries(init.body as Record<string, unknown>)) {
        if (!url.searchParams.has(k)) url.searchParams.set(k, typeof v === "string" ? v : JSON.stringify(v));
      }
    }
    const res = await this.fetchImpl(url.toString(), { method, headers, body, redirect: "manual" });
    const text = await res.text();
    return { status: res.status, body: text, method, path: url.pathname + url.search };
  }
}

export type TargetResponse = Awaited<ReturnType<Target["request"]>>;
