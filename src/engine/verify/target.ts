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

/**
 * How the PoC requests authenticate:
 * - token:   a bearer token sent as `Authorization: Bearer …` (the default).
 * - login:   credentials posted to a local login route that returns a bearer token in a JSON field.
 * - session: credentials posted to a login route that replies with a `Set-Cookie` (express-session &c.); the cookie
 *            is captured and sent on every later request.
 * - cookie:  a pre-supplied raw `Cookie` header value, used as-is.
 */
export type AuthConfig =
  | { kind: "none" }
  | { kind: "token"; token: string }
  | { kind: "login"; path: string; body: Record<string, unknown>; tokenField: string }
  | { kind: "session"; path: string; body: Record<string, unknown> }
  | { kind: "cookie"; cookie: string };

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
  /** Captured cookies (name → value), sent on later requests for session/cookie auth. */
  private readonly jar = new Map<string, string>();
  private sessionReady = false;

  constructor(opts: TargetOptions) {
    this.base = assertLocalTarget(opts.url);
    this.auth = opts.auth ?? { kind: "none" };
    this.fetchImpl = opts.fetch ?? ((url, init) => fetch(url, init));
    if (this.auth.kind === "token") this.bearer = this.auth.token;
  }

  /** True when this target authenticates with a session cookie (login flow or a pre-supplied cookie). */
  private get usesCookies(): boolean {
    return this.auth.kind === "session" || this.auth.kind === "cookie";
  }

  /** The resolved bearer token (exchanging login credentials on first use), for callers that drive a browser. */
  async bearerToken(): Promise<string | undefined> {
    return this.token();
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

  /**
   * Establishes a session once: for `cookie` auth seeds the jar from the supplied header; for `session` auth posts the
   * login credentials and captures the `Set-Cookie` the server replies with (a 2xx or a 302 both count — a redirect
   * after login is normal). Throws when the login set no cookie. A no-op for bearer/token/none.
   */
  private async ensureSession(): Promise<void> {
    if (this.sessionReady || !this.usesCookies) return;
    this.sessionReady = true;
    if (this.auth.kind === "cookie") {
      this.loadCookieHeader(this.auth.cookie);
      return;
    }
    if (this.auth.kind === "session") {
      const res = await this.send("POST", this.auth.path, { body: this.auth.body });
      if (this.jar.size === 0) {
        throw new TargetError(`session login to ${this.auth.path} set no cookie (status ${res.status}) — check the credentials and login path`);
      }
    }
  }

  /** Parses a raw `Cookie` header ("a=1; b=2") into the jar. */
  private loadCookieHeader(raw: string): void {
    for (const pair of raw.split(";")) {
      const eq = pair.indexOf("=");
      if (eq > 0) this.jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  /** Records the `Set-Cookie` cookies of a response into the jar (name=value, dropping attributes). */
  private captureCookies(res: Response): void {
    const getSetCookie = (res.headers as { getSetCookie?: () => string[] }).getSetCookie;
    const cookies = getSetCookie ? getSetCookie.call(res.headers) : (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")!] : []);
    for (const c of cookies) {
      const first = c.split(";")[0];
      const eq = first.indexOf("=");
      if (eq > 0) this.jar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
    }
  }

  private cookieHeader(): string | undefined {
    if (this.jar.size === 0) return undefined;
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  /** Sends one request to the target. `authenticated` adds the configured credential (default true). */
  async request(method: string, path: string, init: { query?: Record<string, string>; body?: unknown; authenticated?: boolean } = {}) {
    const headers: Record<string, string> = {};
    if (init.authenticated !== false) {
      if (this.usesCookies) {
        await this.ensureSession();
      } else {
        const token = await this.token();
        if (token) headers.Authorization = `Bearer ${token}`;
      }
    }
    return this.send(method, path, { query: init.query, body: init.body, headers });
  }

  private async send(method: string, path: string, init: { query?: Record<string, string>; body?: unknown; headers?: Record<string, string> }) {
    const url = new URL(this.base + (path.startsWith("/") ? path : `/${path}`));
    for (const [k, v] of Object.entries(init.query ?? {})) url.searchParams.set(k, v);
    assertLocalTarget(url.toString()); // defense in depth: a crafted path cannot redirect us off-host
    const headers = { ...init.headers };
    const cookie = this.usesCookies ? this.cookieHeader() : undefined; // only cookie-auth targets carry a jar; bearer flow is unchanged
    if (cookie) headers.Cookie = cookie;
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
    if (this.usesCookies) this.captureCookies(res); // keep the jar current (login sets it; some apps rotate it)
    const text = await res.text();
    return { status: res.status, body: text, method, path: url.pathname + url.search, sent: body };
  }
}

export type TargetResponse = Awaited<ReturnType<Target["request"]>>;
