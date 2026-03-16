import { describe, it, expect, beforeEach, afterEach } from "bun:test";

import type { Result } from "@/common/types/result";
import { Ok } from "@/common/types/result";
import type { Config, ProvidersConfig } from "@/node/config";
import type { ProviderService } from "@/node/services/providerService";
import type { WindowService } from "@/node/services/windowService";
import type { ClaudeOauthAuth } from "@/node/utils/claudeOauthAuth";
import { ClaudeOauthService } from "./claudeOauthService";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a claims object into a fake JWT (header.payload.signature). */
function fakeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.fakesig`;
}

/** Build a valid ClaudeOauthAuth that expires far in the future. */
function validAuth(overrides?: Partial<ClaudeOauthAuth>): ClaudeOauthAuth {
  return {
    type: "oauth",
    access: fakeJwt({ sub: "user" }),
    refresh: "rt_test",
    expires: Date.now() + 3_600_000, // 1h from now
    ...overrides,
  };
}

/** Build a ClaudeOauthAuth that is already expired. */
function expiredAuth(overrides?: Partial<ClaudeOauthAuth>): ClaudeOauthAuth {
  return validAuth({ expires: Date.now() - 60_000, ...overrides });
}

/** Build a mock fetch Response for token refresh. */
function mockRefreshResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

interface MockDeps {
  providersConfig: ProvidersConfig;
  setConfigValueCalls: Array<{ provider: string; keyPath: string[]; value: unknown }>;
  focusCalls: number;
}

function createMockDeps(): MockDeps {
  return {
    providersConfig: {},
    setConfigValueCalls: [],
    focusCalls: 0,
  };
}

function createMockConfig(deps: MockDeps): Pick<Config, "loadProvidersConfig"> {
  return {
    loadProvidersConfig: () => deps.providersConfig,
  };
}

function createMockProviderService(deps: MockDeps): Pick<ProviderService, "setConfigValue"> {
  return {
    setConfigValue: (
      provider: string,
      keyPath: string[],
      value: unknown
    ): Promise<Result<void, string>> => {
      deps.setConfigValueCalls.push({ provider, keyPath, value });
      // Also update the in-memory config so readStoredAuth() sees the write
      if (provider === "anthropic" && keyPath[0] === "claudeOauth") {
        if (value === undefined) {
          const anthropic = deps.providersConfig.anthropic;
          if (anthropic) {
            delete anthropic.claudeOauth;
          }
        } else {
          deps.providersConfig.anthropic ??= {};
          deps.providersConfig.anthropic.claudeOauth = value;
        }
      }
      return Promise.resolve(Ok(undefined));
    },
  };
}

function createMockWindowService(deps: MockDeps): Pick<WindowService, "focusMainWindow"> {
  return {
    focusMainWindow: () => {
      deps.focusCalls++;
    },
  };
}

function createService(deps: MockDeps): ClaudeOauthService {
  return new ClaudeOauthService(
    createMockConfig(deps) as Config,
    createMockProviderService(deps) as ProviderService,
    createMockWindowService(deps) as WindowService
  );
}

// Helper to mock globalThis.fetch without needing the `preconnect` property.
function mockFetch(fn: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = Object.assign(fn, {
    preconnect: (_url: string | URL) => {
      // no-op in tests
    },
  }) as typeof fetch;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ClaudeOauthService", () => {
  let deps: MockDeps;
  let service: ClaudeOauthService;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    deps = createMockDeps();
    service = createService(deps);
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    await service.dispose();
  });

  // -------------------------------------------------------------------------
  // getValidAuth - basic
  // -------------------------------------------------------------------------

  describe("getValidAuth", () => {
    it("returns error when no auth is stored", async () => {
      const result = await service.getValidAuth();
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain("not configured");
      }
    });

    it("returns stored auth when token is not expired", async () => {
      const auth = validAuth();
      deps.providersConfig = { anthropic: { claudeOauth: auth } };

      const result = await service.getValidAuth();
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.access).toBe(auth.access);
      }
    });

    it("triggers refresh when expired, returns new auth", async () => {
      const expired = expiredAuth();
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      const newAccessToken = fakeJwt({ sub: "refreshed" });

      mockFetch(() =>
        Promise.resolve(
          mockRefreshResponse({
            access_token: newAccessToken,
            refresh_token: "rt_new",
            expires_in: 3600,
          })
        )
      );

      const result = await service.getValidAuth();
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.access).toBe(newAccessToken);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Token refresh coalescing (AsyncMutex)
  // -------------------------------------------------------------------------

  describe("token refresh coalescing", () => {
    it("only triggers one refresh for concurrent getValidAuth calls with expired tokens", async () => {
      const expired = expiredAuth();
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      let fetchCallCount = 0;
      const newAccessToken = fakeJwt({ sub: "refreshed" });

      mockFetch(async () => {
        fetchCallCount++;
        // Simulate a small delay so both callers are waiting
        await new Promise((resolve) => setTimeout(resolve, 10));
        return mockRefreshResponse({
          access_token: newAccessToken,
          refresh_token: "rt_new",
          expires_in: 3600,
        });
      });

      // Fire 3 concurrent calls
      const results = await Promise.all([
        service.getValidAuth(),
        service.getValidAuth(),
        service.getValidAuth(),
      ]);

      // Only ONE fetch should have happened thanks to AsyncMutex
      expect(fetchCallCount).toBe(1);

      // All three results should be successful with the refreshed token
      for (const result of results) {
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.access).toBe(newAccessToken);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // disconnect
  // -------------------------------------------------------------------------

  describe("disconnect", () => {
    it("clears stored claudeOauth via providerService.setConfigValue", async () => {
      const result = await service.disconnect();
      expect(result.success).toBe(true);
      expect(deps.setConfigValueCalls).toHaveLength(1);
      expect(deps.setConfigValueCalls[0]).toEqual({
        provider: "anthropic",
        keyPath: ["claudeOauth"],
        value: undefined,
      });
    });

    it("subsequent getValidAuth returns error after disconnect", async () => {
      const auth = validAuth();
      deps.providersConfig = { anthropic: { claudeOauth: auth } };

      // Verify auth works first
      const before = await service.getValidAuth();
      expect(before.success).toBe(true);

      // Disconnect
      await service.disconnect();

      // Now getValidAuth should fail — need a fresh service to clear cached auth
      const freshService = createService(deps);
      const after = await freshService.getValidAuth();
      expect(after.success).toBe(false);
      if (!after.success) {
        expect(after.error).toContain("not configured");
      }
      await freshService.dispose();
    });
  });

  // -------------------------------------------------------------------------
  // Desktop flow basics
  // -------------------------------------------------------------------------

  describe("startDesktopFlow", () => {
    it("starts HTTP server and returns flowId + authorizeUrl", async () => {
      const result = await service.startDesktopFlow();
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.flowId).toBeTruthy();
        expect(result.data.authorizeUrl).toContain("https://auth.anthropic.com/oauth/authorize");
        expect(result.data.authorizeUrl).toContain("state=");
        expect(result.data.authorizeUrl).toContain("code_challenge=");
        expect(result.data.authorizeUrl).toContain("code_challenge_method=S256");
      }
    });

    it("authorize URL contains correct parameters", async () => {
      const result = await service.startDesktopFlow();
      expect(result.success).toBe(true);
      if (result.success) {
        const url = new URL(result.data.authorizeUrl);
        expect(url.searchParams.get("response_type")).toBe("code");
        expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:1456/auth/callback");
        expect(url.searchParams.get("state")).toBe(result.data.flowId);
      }
    });

    it("each flow gets a unique flowId", async () => {
      const first = await service.startDesktopFlow();
      expect(first.success).toBe(true);
      // Clean up the first server so the second can use port 1456
      if (first.success) {
        await service.cancelDesktopFlow(first.data.flowId);
      }

      const second = await service.startDesktopFlow();
      expect(second.success).toBe(true);
      if (first.success && second.success) {
        expect(first.data.flowId).not.toBe(second.data.flowId);
      }
    });
  });

  describe("cancelDesktopFlow", () => {
    it("resolves waitForDesktopFlow with cancellation error", async () => {
      const startResult = await service.startDesktopFlow();
      expect(startResult.success).toBe(true);
      if (!startResult.success) return;

      const flowId = startResult.data.flowId;

      // Start waiting (don't await yet)
      const waitPromise = service.waitForDesktopFlow(flowId, { timeoutMs: 5000 });

      // Cancel the flow
      await service.cancelDesktopFlow(flowId);

      const result = await waitPromise;
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain("cancelled");
      }
    });
  });

  // -------------------------------------------------------------------------
  // Invalid grant cleanup
  // -------------------------------------------------------------------------

  describe("invalid grant cleanup", () => {
    it("calls disconnect + clears stored auth on invalid_grant response", async () => {
      const expired = expiredAuth();
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      mockFetch(() =>
        Promise.resolve(
          new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          })
        )
      );

      const result = await service.getValidAuth();
      expect(result.success).toBe(false);

      // Should have called setConfigValue to clear auth (disconnect)
      const clearCall = deps.setConfigValueCalls.find(
        (c) =>
          c.provider === "anthropic" && c.keyPath[0] === "claudeOauth" && c.value === undefined
      );
      expect(clearCall).toBeDefined();
    });

    it("clears auth when error text contains 'revoked'", async () => {
      const expired = expiredAuth();
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      mockFetch(() =>
        Promise.resolve(
          new Response("Token has been revoked", {
            status: 401,
          })
        )
      );

      const result = await service.getValidAuth();
      expect(result.success).toBe(false);

      const clearCall = deps.setConfigValueCalls.find(
        (c) =>
          c.provider === "anthropic" && c.keyPath[0] === "claudeOauth" && c.value === undefined
      );
      expect(clearCall).toBeDefined();
    });

    it("subsequent getValidAuth returns error after invalid_grant cleanup", async () => {
      const expired = expiredAuth();
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      mockFetch(() =>
        Promise.resolve(
          new Response(JSON.stringify({ error: "invalid_grant" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          })
        )
      );

      // First call triggers disconnect
      await service.getValidAuth();

      // Second call should see no stored auth
      const result = await service.getValidAuth();
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain("not configured");
      }
    });
  });

  // -------------------------------------------------------------------------
  // Refresh preserves organizationId
  // -------------------------------------------------------------------------

  describe("refresh preserves organizationId", () => {
    it("keeps previous organizationId when refreshed token has no org info", async () => {
      const expired = expiredAuth({ organizationId: "org_original" });
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      // Refreshed token has no organization_id in JWT claims
      const newAccessToken = fakeJwt({ sub: "user" });

      mockFetch(() =>
        Promise.resolve(
          mockRefreshResponse({
            access_token: newAccessToken,
            refresh_token: "rt_new",
            expires_in: 3600,
          })
        )
      );

      const result = await service.getValidAuth();
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.organizationId).toBe("org_original");
      }
    });
  });

  // -------------------------------------------------------------------------
  // Refresh keeps old refresh token when server doesn't rotate it
  // -------------------------------------------------------------------------

  describe("refresh token rotation", () => {
    it("keeps old refresh token when server does not return a new one", async () => {
      const expired = expiredAuth({ refresh: "rt_keep_me" });
      deps.providersConfig = { anthropic: { claudeOauth: expired } };

      mockFetch(() =>
        Promise.resolve(
          mockRefreshResponse({
            access_token: fakeJwt({ sub: "user" }),
            expires_in: 3600,
            // No refresh_token in response
          })
        )
      );

      const result = await service.getValidAuth();
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.refresh).toBe("rt_keep_me");
      }
    });
  });
});
