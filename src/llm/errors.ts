// Human-readable messages for Meta Model API / config errors, shared by the CLI and the smoke test.
import {
  APIConnectionError,
  APIConnectionTimeoutError,
  APIError,
  AuthenticationError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
} from "openai";
import { MetaConfigError } from "./meta-client.js";

export function describeApiError(err: unknown): string {
  const baseURL = process.env.META_BASE_URL;
  if (err instanceof MetaConfigError) return err.message;
  if (err instanceof AuthenticationError) return `401 auth error — META_API_KEY is missing or invalid. (${err.message})`;
  if (err instanceof PermissionDeniedError) return `403 permission denied — key lacks access to this model. (${err.message})`;
  if (err instanceof NotFoundError) return `404 not found — check META_MODEL and META_BASE_URL. (${err.message})`;
  if (err instanceof RateLimitError) return `429 rate limited / quota exceeded. (${err.message})`;
  if (err instanceof APIConnectionTimeoutError) return `request timed out reaching ${baseURL}.`;
  if (err instanceof APIConnectionError) return `network error reaching ${baseURL} — check connectivity / base URL. (${err.message})`;
  if (err instanceof APIError) return `API error ${err.status ?? ""}: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

/** Loads ./.env into process.env if present; otherwise relies on variables already in the shell. */
export function loadDotEnv(): void {
  try {
    process.loadEnvFile(".env");
  } catch {
    // no .env file
  }
}
