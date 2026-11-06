/**
 * Attestry API client for MCP server tools.
 * Authenticates via API key and calls the Attestry REST API.
 *
 * The default base URL is https://attestry.ai, the canonical Attestry API
 * host (the same default as @attestry/sdk). Override with ATTESTRY_API_URL
 * for self-hosted or staging deployments.
 */

const DEFAULT_API_URL = "https://attestry.ai";

export interface AttestryClientConfig {
  apiKey: string;
  apiUrl: string;
}

export function getConfig(): AttestryClientConfig {
  const apiKey = process.env.ATTESTRY_API_KEY;
  if (!apiKey) {
    throw new Error(
      "ATTESTRY_API_KEY environment variable is required. " +
        "Create an API key at https://attestry.ai/settings -> Integrations -> API Keys."
    );
  }

  return {
    apiKey,
    apiUrl: (process.env.ATTESTRY_API_URL || DEFAULT_API_URL).replace(/\/$/, ""),
  };
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  fieldErrors?: Record<string, unknown>;
  /**
   * The kernel error envelope's machine-readable leg ({success:false, error,
   * details}) — `details.code` carries the typed `annex_iv.*` / api error code
   * the SDK and dashboard branch on (route-errors.ts:22); a 422
   * `annex_iv.validation_failed` additionally carries `details.issues`. The
   * wire always had it; the type previously dropped it (③ H fix, 2026-06-10).
   */
  details?: { code?: string; issues?: unknown } & Record<string, unknown>;
}

export async function apiGet<T = unknown>(
  path: string,
  params?: Record<string, string | undefined>
): Promise<ApiResponse<T>> {
  const config = getConfig();
  const url = new URL(path, config.apiUrl);

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) {
        url.searchParams.set(key, value);
      }
    }
  }

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      // Attestry only accepts x-api-key for inbound API calls — never Bearer.
      "x-api-key": config.apiKey,
      Accept: "application/json",
      "User-Agent": "attestry-mcp-server/1.1.0",
    },
  });

  return (await response.json()) as ApiResponse<T>;
}

export async function apiPost<T = unknown>(
  path: string,
  body: Record<string, unknown>
): Promise<ApiResponse<T>> {
  const config = getConfig();
  const url = new URL(path, config.apiUrl);

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      // Attestry only accepts x-api-key for inbound API calls — never Bearer.
      "x-api-key": config.apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "attestry-mcp-server/1.1.0",
    },
    body: JSON.stringify(body),
  });

  return (await response.json()) as ApiResponse<T>;
}
