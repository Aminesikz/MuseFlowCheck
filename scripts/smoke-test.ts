// Smoke test: verifies the Meta Model API key, base URL and model id work end to end.
import {
  APIConnectionError,
  APIConnectionTimeoutError,
  APIError,
  AuthenticationError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
} from "openai";
import { complete, loadMetaConfig, MetaConfigError } from "../src/llm/meta-client.js";

const PROMPT = 'Reply with exactly this JSON object and nothing else: {"status":"ok"}';

function fail(message: string): never {
  console.error(`\n✗ Smoke test FAILED: ${message}`);
  process.exit(1);
}

function describeError(err: unknown): string {
  if (err instanceof MetaConfigError) return err.message;
  if (err instanceof AuthenticationError) return `401 auth error — META_API_KEY is missing or invalid. (${err.message})`;
  if (err instanceof PermissionDeniedError) return `403 permission denied — key lacks access to this model. (${err.message})`;
  if (err instanceof NotFoundError) return `404 not found — check META_MODEL and META_BASE_URL. (${err.message})`;
  if (err instanceof RateLimitError) return `429 rate limited / quota exceeded. (${err.message})`;
  if (err instanceof APIConnectionTimeoutError) return `request timed out reaching ${process.env.META_BASE_URL}.`;
  if (err instanceof APIConnectionError) return `network error reaching ${process.env.META_BASE_URL} — check connectivity / base URL. (${err.message})`;
  if (err instanceof APIError) return `API error ${err.status ?? ""}: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

/** Models sometimes wrap JSON in ```json fences; strip them before parsing. */
function extractJson(text: string): unknown {
  const unfenced = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  return JSON.parse(unfenced);
}

async function main(): Promise<void> {
  try {
    process.loadEnvFile(".env");
  } catch {
    // No .env file: fall back to variables already set in the shell.
  }

  let config;
  try {
    config = loadMetaConfig();
  } catch (err) {
    fail(describeError(err));
  }

  console.log(`→ POST ${config.baseURL}/responses  model=${config.model}`);

  let raw: string;
  try {
    raw = await complete(PROMPT, config);
  } catch (err) {
    fail(describeError(err));
  }

  console.log("\nRaw response:");
  console.log(raw);

  let parsed: unknown;
  try {
    parsed = extractJson(raw);
  } catch {
    fail("the API responded, but the text was not valid JSON (see raw response above).");
  }

  console.log("\nParsed result:");
  console.log(parsed);

  if ((parsed as { status?: unknown })?.status !== "ok") {
    fail('parsed JSON did not contain "status": "ok".');
  }

  console.log("\n✓ Smoke test passed — Meta Model API is reachable and authenticated.");
}

main().catch((err) => fail(describeError(err)));
