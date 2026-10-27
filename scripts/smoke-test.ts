// Smoke test: verifies the Meta Model API key, base URL and model id work end to end.
import { describeApiError as describeError, loadDotEnv } from "../src/llm/errors.js";
import { complete, loadMetaConfig } from "../src/llm/meta-client.js";

const PROMPT = 'Reply with exactly this JSON object and nothing else: {"status":"ok"}';

function fail(message: string): never {
  console.error(`\n✗ Smoke test FAILED: ${message}`);
  process.exit(1);
}

/** Models sometimes wrap JSON in ```json fences; strip them before parsing. */
function extractJson(text: string): unknown {
  const unfenced = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  return JSON.parse(unfenced);
}

async function main(): Promise<void> {
  loadDotEnv();

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
