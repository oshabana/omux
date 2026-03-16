# Phase 02: Provider Factory Token Injection & Request Routing

This phase wires Claude OAuth into the provider model factory so that when a user has Claude OAuth tokens stored, Anthropic API requests are automatically authenticated with the OAuth bearer token instead of requiring an API key. This is the critical bridge between "tokens exist" and "chat actually works."

## Important Context

The Codex OAuth integration in `src/node/services/providerModelFactory.ts` is the template. Key differences for Claude:
- **No endpoint rewrite:** Unlike Codex (which routes to `chatgpt.com/backend-api/codex/responses`), Claude OAuth tokens work against the standard `api.anthropic.com` API. The fetch wrapper only needs to inject the `Authorization: Bearer <token>` header.
- **No body transformation:** Codex requires lifting system prompts, stripping fields, etc. Claude needs none of that — the Anthropic SDK's normal request format works as-is.
- **Header injection:** Set `Authorization: Bearer <access_token>` and ensure `anthropic-version` header is present. Remove any `x-api-key` header that the SDK might set (since we're using OAuth, not API key auth).
- The `@ai-sdk/anthropic` `createAnthropic` factory accepts a `fetch` option — wrap it to inject OAuth headers.

Reference `providerModelFactory.ts` lines ~800-815 for how the Anthropic provider is currently created, and lines ~945-1130 for the Codex fetch wrapper pattern.

## Tasks

- [x] Add Claude OAuth awareness to `src/node/services/providerModelFactory.ts`:
  - Import `ClaudeOauthService`, `parseClaudeOauthAuth`, `isClaudeOauthAllowedModelId`, `isClaudeOauthRequiredModelId` from the new modules
  - Add `claudeOauthService?: ClaudeOauthService` to the constructor (same pattern as `codexOauthService?`)
  - In the Anthropic provider creation section (~line 800):
    - Read `providerConfig.claudeOauth` and parse with `parseClaudeOauthAuth`
    - Determine `shouldRouteThroughClaudeOauth` using the same logic pattern as Codex:
      - Check `isClaudeOauthRequiredModelId(fullModelId)` and `isClaudeOauthAllowedModelId(fullModelId)`
      - If OAuth required and no stored auth → return error
      - If OAuth allowed and stored auth exists → use OAuth
    - When routing through OAuth:
      - Set `apiKey: "claude-oauth"` as placeholder (the real token goes in fetch headers)
      - Wrap the existing `providerFetch` with a new layer that:
        1. Calls `claudeOauthService.getValidAuth()` to get a fresh token (handles refresh)
        2. Clones/creates `Headers` and sets `Authorization: Bearer ${auth.access}`
        3. Deletes any `x-api-key` header the SDK may have set
        4. Passes through to the underlying fetch
      - Keep the existing `wrapFetchWithAnthropicCacheControl` in the chain — OAuth fetch wraps around it
  - Ensure the fetch wrapper only intercepts Anthropic API calls (check URL contains `anthropic.com` or matches the base URL)

- [x] Wire `ClaudeOauthService` into `ProviderModelFactory` instantiation:
  - In `src/node/services/serviceContainer.ts`: pass `this.claudeOauthService` to the `ProviderModelFactory` constructor
  - In `src/cli/run.ts`: pass the `claudeOauthService` to the factory (search for where `codexOauthService` is passed and mirror)
  - Check `src/node/services/aiService.ts` for a `setCodexOauthService` pattern — add matching `setClaudeOauthService` if needed

- [x] Handle the "no API key needed" flow for Anthropic:
  - Currently, if `anthropic.apiKey` is missing, the provider likely errors out before reaching the fetch wrapper
  - When `shouldRouteThroughClaudeOauth` is true, the factory must skip the API key requirement check for Anthropic
  - Search for where API key validation happens for Anthropic (likely in `resolveApiKey` or similar) and add an early-out when Claude OAuth is configured
  - The `apiKey: "claude-oauth"` placeholder should satisfy the SDK's constructor requirement

- [x] Verify compilation and basic smoke test:
  - Run `make typecheck` — fix any errors
  - Run `make lint-fix`
  - Manually verify the logic by reading through the modified factory code to confirm:
    - OAuth tokens are injected on Anthropic requests
    - Non-OAuth Anthropic requests (API key users) are unaffected
    - Token refresh happens automatically via `getValidAuth()`
