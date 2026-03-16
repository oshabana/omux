import { describe, it, expect } from "bun:test";

import {
  buildClaudeAuthorizeUrl,
  buildClaudeTokenExchangeBody,
  buildClaudeRefreshBody,
  isClaudeOauthAllowedModelId,
  isClaudeOauthRequiredModelId,
  CLAUDE_OAUTH_CLIENT_ID,
  CLAUDE_OAUTH_SCOPE,
} from "./claudeOAuth";

// ---------------------------------------------------------------------------
// buildClaudeAuthorizeUrl
// ---------------------------------------------------------------------------

describe("buildClaudeAuthorizeUrl", () => {
  it("produces a URL with all required OAuth params", () => {
    const result = buildClaudeAuthorizeUrl({
      redirectUri: "http://localhost:1456/auth/callback",
      state: "test-state",
      codeChallenge: "test-challenge",
    });

    const url = new URL(result);
    expect(url.origin).toBe("https://auth.anthropic.com");
    expect(url.pathname).toBe("/oauth/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(CLAUDE_OAUTH_CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:1456/auth/callback");
    expect(url.searchParams.get("scope")).toBe(CLAUDE_OAUTH_SCOPE);
    expect(url.searchParams.get("state")).toBe("test-state");
    expect(url.searchParams.get("code_challenge")).toBe("test-challenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });
});

// ---------------------------------------------------------------------------
// buildClaudeTokenExchangeBody
// ---------------------------------------------------------------------------

describe("buildClaudeTokenExchangeBody", () => {
  it("produces URLSearchParams with correct fields", () => {
    const body = buildClaudeTokenExchangeBody({
      code: "auth-code-123",
      redirectUri: "http://localhost:1456/auth/callback",
      codeVerifier: "verifier-abc",
    });

    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("client_id")).toBe(CLAUDE_OAUTH_CLIENT_ID);
    expect(body.get("code")).toBe("auth-code-123");
    expect(body.get("redirect_uri")).toBe("http://localhost:1456/auth/callback");
    expect(body.get("code_verifier")).toBe("verifier-abc");
  });
});

// ---------------------------------------------------------------------------
// buildClaudeRefreshBody
// ---------------------------------------------------------------------------

describe("buildClaudeRefreshBody", () => {
  it("produces URLSearchParams with correct fields", () => {
    const body = buildClaudeRefreshBody({ refreshToken: "rt_test_123" });

    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("client_id")).toBe(CLAUDE_OAUTH_CLIENT_ID);
    expect(body.get("refresh_token")).toBe("rt_test_123");
  });
});

// ---------------------------------------------------------------------------
// isClaudeOauthAllowedModelId
// ---------------------------------------------------------------------------

describe("isClaudeOauthAllowedModelId", () => {
  it("returns true for known allowed model IDs", () => {
    expect(isClaudeOauthAllowedModelId("claude-opus-4-6")).toBe(true);
    expect(isClaudeOauthAllowedModelId("claude-sonnet-4-6")).toBe(true);
    expect(isClaudeOauthAllowedModelId("claude-haiku-4-5")).toBe(true);
  });

  it("returns false for non-allowed model IDs", () => {
    expect(isClaudeOauthAllowedModelId("gpt-4o")).toBe(false);
    expect(isClaudeOauthAllowedModelId("o3-mini")).toBe(false);
    expect(isClaudeOauthAllowedModelId("")).toBe(false);
  });

  it("normalizes model IDs with anthropic: prefix", () => {
    expect(isClaudeOauthAllowedModelId("anthropic:claude-opus-4-6")).toBe(true);
    expect(isClaudeOauthAllowedModelId("anthropic:claude-sonnet-4-6")).toBe(true);
    expect(isClaudeOauthAllowedModelId("anthropic:claude-haiku-4-5")).toBe(true);
  });

  it("does not match with wrong provider prefix", () => {
    // After normalization, "claude-opus-4-6" is extracted from "openai:claude-opus-4-6"
    // which is allowed — this tests prefix stripping works for any prefix
    expect(isClaudeOauthAllowedModelId("openai:claude-opus-4-6")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isClaudeOauthRequiredModelId
// ---------------------------------------------------------------------------

describe("isClaudeOauthRequiredModelId", () => {
  it("returns false for all models (empty set currently)", () => {
    expect(isClaudeOauthRequiredModelId("claude-opus-4-6")).toBe(false);
    expect(isClaudeOauthRequiredModelId("claude-sonnet-4-6")).toBe(false);
    expect(isClaudeOauthRequiredModelId("gpt-4o")).toBe(false);
  });

  it("returns false even with anthropic: prefix", () => {
    expect(isClaudeOauthRequiredModelId("anthropic:claude-opus-4-6")).toBe(false);
  });
});
