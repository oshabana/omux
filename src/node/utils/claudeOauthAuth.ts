/**
 * Claude OAuth token parsing + validation.
 *
 * We intentionally do not validate token signatures here; we only need to
 * check shape and expiry of OAuth responses from Anthropic.
 */

import { parseJwtClaims } from "@/node/utils/codexOauthAuth";

export interface ClaudeOauthAuth {
  type: "oauth";
  /** OAuth access token. */
  access: string;
  /** OAuth refresh token. */
  refresh: string;
  /** Unix epoch milliseconds when the access token expires. */
  expires: number;
  /** Anthropic organization id (if present in token claims). */
  organizationId?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function parseClaudeOauthAuth(value: unknown): ClaudeOauthAuth | null {
  if (!isPlainObject(value)) {
    return null;
  }

  const type = value.type;
  const access = value.access;
  const refresh = value.refresh;
  const expires = value.expires;
  const organizationId = value.organizationId;

  if (type !== "oauth") return null;
  if (typeof access !== "string" || !access) return null;
  if (typeof refresh !== "string" || !refresh) return null;
  if (typeof expires !== "number" || !Number.isFinite(expires)) return null;

  if (typeof organizationId !== "undefined") {
    if (typeof organizationId !== "string" || !organizationId) return null;
  }

  return { type: "oauth", access, refresh, expires, organizationId };
}

export function isClaudeOauthAuthExpired(
  auth: ClaudeOauthAuth,
  opts?: { nowMs?: number; skewMs?: number }
): boolean {
  const now = opts?.nowMs ?? Date.now();
  const skew = opts?.skewMs ?? 30_000;
  return now + skew >= auth.expires;
}

/**
 * Extract organization id from Claude OAuth JWT claims.
 */
/**
 * Detect whether an error response from Anthropic's token endpoint indicates
 * the grant has been revoked or is otherwise permanently invalid.
 * Checks for `invalid_grant`, `revoked`, or `unauthorized` signals.
 */
export function isClaudeOauthAuthRevoked(errorText: string): boolean {
  const trimmed = errorText.trim();
  if (trimmed.length === 0) {
    return false;
  }

  try {
    const json = JSON.parse(trimmed) as unknown;
    if (isPlainObject(json)) {
      const err = typeof json.error === "string" ? json.error.toLowerCase() : "";
      if (err === "invalid_grant" || err === "unauthorized") {
        return true;
      }
    }
  } catch {
    // Ignore parse failures — fall back to substring checks.
  }

  const lower = trimmed.toLowerCase();
  return (
    lower.includes("invalid_grant") ||
    lower.includes("revoked") ||
    lower.includes("unauthorized")
  );
}

export function extractOrganizationIdFromToken(token: string): string | null {
  const claims = parseJwtClaims(token);
  if (!claims) {
    return null;
  }

  // Check for organization_id in claims.
  const orgId = claims.organization_id;
  if (typeof orgId === "string" && orgId) {
    return orgId;
  }

  return null;
}

export function extractOrganizationIdFromTokens(input: {
  accessToken: string;
  idToken?: string;
}): string | null {
  // Prefer id_token when present; fall back to access token.
  if (typeof input.idToken === "string" && input.idToken) {
    const fromId = extractOrganizationIdFromToken(input.idToken);
    if (fromId) {
      return fromId;
    }
  }

  return extractOrganizationIdFromToken(input.accessToken);
}
