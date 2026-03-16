import { describe, it, expect } from "bun:test";

import {
  parseClaudeOauthAuth,
  isClaudeOauthAuthExpired,
  extractOrganizationIdFromToken,
  extractOrganizationIdFromTokens,
} from "./claudeOauthAuth";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a claims object into a fake JWT (header.payload.signature). */
function fakeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.fakesig`;
}

// ---------------------------------------------------------------------------
// parseClaudeOauthAuth
// ---------------------------------------------------------------------------

describe("parseClaudeOauthAuth", () => {
  it("accepts a valid object with all required fields", () => {
    const input = {
      type: "oauth" as const,
      access: "at_123",
      refresh: "rt_456",
      expires: Date.now() + 60_000,
    };
    const result = parseClaudeOauthAuth(input);
    expect(result).toEqual(input);
  });

  it("accepts a valid object with optional organizationId", () => {
    const input = {
      type: "oauth" as const,
      access: "at_123",
      refresh: "rt_456",
      expires: Date.now() + 60_000,
      organizationId: "org_abc",
    };
    const result = parseClaudeOauthAuth(input);
    expect(result).toEqual(input);
  });

  it("returns null for non-object values", () => {
    expect(parseClaudeOauthAuth(null)).toBeNull();
    expect(parseClaudeOauthAuth(undefined)).toBeNull();
    expect(parseClaudeOauthAuth("string")).toBeNull();
    expect(parseClaudeOauthAuth(42)).toBeNull();
    expect(parseClaudeOauthAuth([])).toBeNull();
  });

  it("returns null when type is not 'oauth'", () => {
    expect(
      parseClaudeOauthAuth({ type: "api-key", access: "a", refresh: "r", expires: 123 })
    ).toBeNull();
  });

  it("returns null when access is missing or empty", () => {
    expect(
      parseClaudeOauthAuth({ type: "oauth", access: "", refresh: "r", expires: 123 })
    ).toBeNull();
    expect(parseClaudeOauthAuth({ type: "oauth", refresh: "r", expires: 123 })).toBeNull();
  });

  it("returns null when refresh is missing or empty", () => {
    expect(
      parseClaudeOauthAuth({ type: "oauth", access: "a", refresh: "", expires: 123 })
    ).toBeNull();
  });

  it("returns null when expires is not a finite number", () => {
    expect(
      parseClaudeOauthAuth({ type: "oauth", access: "a", refresh: "r", expires: NaN })
    ).toBeNull();
    expect(
      parseClaudeOauthAuth({ type: "oauth", access: "a", refresh: "r", expires: Infinity })
    ).toBeNull();
    expect(
      parseClaudeOauthAuth({ type: "oauth", access: "a", refresh: "r", expires: "soon" })
    ).toBeNull();
  });

  it("returns null when organizationId is present but empty string", () => {
    expect(
      parseClaudeOauthAuth({
        type: "oauth",
        access: "a",
        refresh: "r",
        expires: 123,
        organizationId: "",
      })
    ).toBeNull();
  });

  it("does not pass through extra fields", () => {
    const input = {
      type: "oauth" as const,
      access: "at_123",
      refresh: "rt_456",
      expires: 999,
      extraField: "should not appear",
    };
    const result = parseClaudeOauthAuth(input);
    expect(result).not.toBeNull();
    // The parser constructs a new object with only known fields
    expect(result).toEqual({
      type: "oauth",
      access: "at_123",
      refresh: "rt_456",
      expires: 999,
    });
    expect((result as unknown as Record<string, unknown>).extraField).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// isClaudeOauthAuthExpired
// ---------------------------------------------------------------------------

describe("isClaudeOauthAuthExpired", () => {
  const base = { type: "oauth" as const, access: "a", refresh: "r" };

  it("returns false when token is not yet expired (with default skew)", () => {
    // Token expires 60s from now, default skew is 30s → not expired
    const auth = { ...base, expires: Date.now() + 60_000 };
    expect(isClaudeOauthAuthExpired(auth)).toBe(false);
  });

  it("returns true when token is within the skew window", () => {
    // Token expires in 20s, default skew 30s → expired
    const now = Date.now();
    const auth = { ...base, expires: now + 20_000 };
    expect(isClaudeOauthAuthExpired(auth, { nowMs: now })).toBe(true);
  });

  it("returns true when token is already past expiry", () => {
    const auth = { ...base, expires: Date.now() - 1000 };
    expect(isClaudeOauthAuthExpired(auth)).toBe(true);
  });

  it("respects custom skew", () => {
    const now = 1_000_000;
    const auth = { ...base, expires: now + 5_000 };
    // With 0 skew, not expired
    expect(isClaudeOauthAuthExpired(auth, { nowMs: now, skewMs: 0 })).toBe(false);
    // With 10s skew, expired
    expect(isClaudeOauthAuthExpired(auth, { nowMs: now, skewMs: 10_000 })).toBe(true);
  });

  it("respects custom nowMs override", () => {
    const auth = { ...base, expires: 500_000 };
    // "now" is well before expiry
    expect(isClaudeOauthAuthExpired(auth, { nowMs: 100_000, skewMs: 0 })).toBe(false);
    // "now" is past expiry
    expect(isClaudeOauthAuthExpired(auth, { nowMs: 600_000, skewMs: 0 })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// extractOrganizationIdFromToken / extractOrganizationIdFromTokens
// ---------------------------------------------------------------------------

describe("extractOrganizationIdFromToken", () => {
  it("extracts organization_id from a JWT", () => {
    const token = fakeJwt({ organization_id: "org_from_jwt" });
    expect(extractOrganizationIdFromToken(token)).toBe("org_from_jwt");
  });

  it("returns null for a JWT without organization_id", () => {
    const token = fakeJwt({ sub: "user" });
    expect(extractOrganizationIdFromToken(token)).toBeNull();
  });

  it("returns null for an invalid token", () => {
    expect(extractOrganizationIdFromToken("not-a-jwt")).toBeNull();
  });
});

describe("extractOrganizationIdFromTokens", () => {
  it("prefers id_token over access token", () => {
    const idToken = fakeJwt({ organization_id: "from_id_token" });
    const accessToken = fakeJwt({ organization_id: "from_access_token" });
    expect(extractOrganizationIdFromTokens({ accessToken, idToken })).toBe("from_id_token");
  });

  it("falls back to access token when id_token is missing", () => {
    const accessToken = fakeJwt({ organization_id: "from_access_token" });
    expect(extractOrganizationIdFromTokens({ accessToken })).toBe("from_access_token");
  });

  it("falls back to access token when id_token has no organization_id", () => {
    const idToken = fakeJwt({ sub: "user" });
    const accessToken = fakeJwt({ organization_id: "from_access_token" });
    expect(extractOrganizationIdFromTokens({ accessToken, idToken })).toBe("from_access_token");
  });
});
