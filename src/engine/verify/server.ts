// Runs a patched copy of the target project on a fresh loopback port, for patch proof. Only ever starts a local
// process and only ever builds a loopback Target (which itself re-checks the host).
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { Target, type AuthConfig } from "./target.js";

/** An unused TCP port on the loopback interface. */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => (port ? resolve(port) : reject(new Error("could not find a free port"))));
    });
  });
}

/** Waits until `GET <base><readyPath>` answers (any status) or the timeout elapses. */
async function waitForReady(base: string, readyPath: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await fetch(base + readyPath, { signal: AbortSignal.timeout(1000) });
      return;
    } catch {
      if (Date.now() > deadline) throw new Error(`patched server did not become ready within ${timeoutMs}ms`);
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

export interface PatchedServerOptions {
  /** Shell command that starts the server; it must honor the PORT env var. */
  command: string;
  /** Path polled until the server answers (default "/"). */
  readyPath?: string;
  auth?: AuthConfig;
  timeoutMs?: number;
}

/** Starts the project in `dir` on a fresh port and returns a loopback Target for it plus a stop handle. */
export async function startPatchedServer(dir: string, opts: PatchedServerOptions): Promise<{ target: Target; stop: () => Promise<void> }> {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(opts.command, { cwd: dir, env: { ...process.env, PORT: String(port) }, shell: true, stdio: "ignore", detached: true });
  const stop = () =>
    new Promise<void>((resolve) => {
      if (child.pid === undefined || child.exitCode !== null) return resolve();
      child.once("exit", () => resolve());
      try {
        process.kill(-child.pid, "SIGTERM"); // the process group, so a shell-spawned child dies too
      } catch {
        resolve();
      }
    });
  try {
    await waitForReady(base, opts.readyPath ?? "/", opts.timeoutMs ?? 15000);
  } catch (err) {
    await stop();
    throw err;
  }
  return { target: new Target({ url: base, auth: opts.auth }), stop };
}
