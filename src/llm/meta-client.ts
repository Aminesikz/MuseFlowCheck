// Meta Model API client: thin wrapper over the OpenAI-compatible Responses API (https://dev.meta.ai/docs/quickstart).
import OpenAI from "openai";

export interface MetaConfig {
  apiKey: string;
  baseURL: string;
  model: string;
}

export class MetaConfigError extends Error {}

/** Reads META_API_KEY, META_BASE_URL and META_MODEL from the environment. Nothing is hardcoded. */
export function loadMetaConfig(env: NodeJS.ProcessEnv = process.env): MetaConfig {
  const required = ["META_API_KEY", "META_BASE_URL", "META_MODEL"] as const;
  const missing = required.filter((name) => !env[name]?.trim());
  if (missing.length > 0) {
    throw new MetaConfigError(
      `Missing environment variable(s): ${missing.join(", ")}. Copy .env.example to .env and fill them in.`,
    );
  }
  return {
    apiKey: env.META_API_KEY!.trim(),
    baseURL: env.META_BASE_URL!.trim(),
    model: env.META_MODEL!.trim(),
  };
}

/** Sends a single text prompt to the configured Muse Spark model and returns the response text. */
export async function complete(prompt: string, config: MetaConfig = loadMetaConfig()): Promise<string> {
  const client = new OpenAI({ apiKey: config.apiKey, baseURL: config.baseURL });
  const response = await client.responses.create({ model: config.model, input: prompt });
  return response.output_text;
}
