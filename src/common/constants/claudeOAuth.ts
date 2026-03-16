/**
 * Claude OAuth constants and helpers.
 *
 * Claude (Anthropic subscription) authentication uses Anthropic OAuth tokens
 * rather than a standard Anthropic API key.
 *
 * This module is intentionally shared (common/) so both the backend and future
 * UI can reference the same endpoints and model gating rules.
 */

// NOTE: These endpoints + params follow the Anthropic OAuth guide.
// If Anthropic changes them, keep all updates centralized here.

export const CLAUDE_OAUTH_ORIGIN = "https://auth.anthropic.com";

// Public OAuth client id for Claude Code CLI flows.
//
// The exact value is not a secret, but it is intentionally centralized so we
// can update it without hunting through backend/UI code.
export const CLAUDE_OAUTH_CLIENT_ID = "app_a]a6342b-7a56-4527-a0df-e3c9b34abe72";

export const CLAUDE_OAUTH_AUTHORIZE_URL = `${CLAUDE_OAUTH_ORIGIN}/oauth/authorize`;
export const CLAUDE_OAUTH_TOKEN_URL = `${CLAUDE_OAUTH_ORIGIN}/oauth/token`;

// We request offline_access to receive refresh tokens.
export const CLAUDE_OAUTH_SCOPE = "openid offline_access";

// Desktop browser redirect URI used by the simplified flow.
// Port 1456 to avoid collision with Codex OAuth on port 1455.
export const CLAUDE_OAUTH_BROWSER_REDIRECT_URI = "http://localhost:1456/auth/callback";

// Claude-specific device auth endpoints.
export const CLAUDE_OAUTH_DEVICE_USERCODE_URL = `${CLAUDE_OAUTH_ORIGIN}/api/accounts/deviceauth/usercode`;
export const CLAUDE_OAUTH_DEVICE_TOKEN_POLL_URL = `${CLAUDE_OAUTH_ORIGIN}/api/accounts/deviceauth/token`;
export const CLAUDE_OAUTH_DEVICE_VERIFY_URL = `${CLAUDE_OAUTH_ORIGIN}/claude/device`;

export function buildClaudeAuthorizeUrl(input: {
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): string {
  const url = new URL(CLAUDE_OAUTH_AUTHORIZE_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLAUDE_OAUTH_CLIENT_ID);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("scope", CLAUDE_OAUTH_SCOPE);
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  return url.toString();
}

export function buildClaudeTokenExchangeBody(input: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): URLSearchParams {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", CLAUDE_OAUTH_CLIENT_ID);
  body.set("code", input.code);
  body.set("redirect_uri", input.redirectUri);
  body.set("code_verifier", input.codeVerifier);
  return body;
}

export function buildClaudeRefreshBody(input: { refreshToken: string }): URLSearchParams {
  const body = new URLSearchParams();
  body.set("grant_type", "refresh_token");
  body.set("client_id", CLAUDE_OAUTH_CLIENT_ID);
  body.set("refresh_token", input.refreshToken);
  return body;
}

/**
 * Models that may be routed through the Claude OAuth path.
 *
 * The values in this set are providerModelIds (no `anthropic:` prefix).
 */
export const CLAUDE_OAUTH_ALLOWED_MODELS = new Set<string>([
  "claude-opus-4-6",
  "claude-sonnet-4-6",
  "claude-haiku-4-5",
]);

/**
 * Models that *require* Claude OAuth routing.
 *
 * Empty for now — no models are gated to OAuth-only yet.
 */
export const CLAUDE_OAUTH_REQUIRED_MODELS = new Set<string>([]);

function normalizeClaudeOauthModelId(modelId: string): string {
  // Accept either provider:model or bare model ids and normalize to providerModelId.
  const colonIndex = modelId.indexOf(":");
  if (colonIndex !== -1) {
    return modelId.slice(colonIndex + 1);
  }

  return modelId;
}

export function isClaudeOauthAllowedModelId(modelId: string): boolean {
  return CLAUDE_OAUTH_ALLOWED_MODELS.has(normalizeClaudeOauthModelId(modelId));
}

export function isClaudeOauthRequiredModelId(modelId: string): boolean {
  return CLAUDE_OAUTH_REQUIRED_MODELS.has(normalizeClaudeOauthModelId(modelId));
}
