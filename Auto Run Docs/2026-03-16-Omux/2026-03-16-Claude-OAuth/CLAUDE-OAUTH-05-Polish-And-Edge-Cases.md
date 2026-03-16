# Phase 05: Polish, Edge Cases & End-to-End Verification

This phase handles edge cases, error resilience, and final verification. It ensures the Claude OAuth flow is production-ready: graceful error handling, token revocation detection, proper cleanup on app exit, and a full end-to-end review.

## Important Context

Reference the self-healing and crash resilience guidelines from CLAUDE.md:
- Never let corrupted persisted state brick a workspace
- Startup-time initialization must never crash the app
- Prefer self-healing behavior over hard failures

Also reference the Codex OAuth error handling patterns:
- `isCodexOauthAuthRevoked()` in `codexOauthAuth.ts` detects revoked tokens
- `OAuthFlowManager.shutdownAll()` cleans up on app exit
- The Codex fetch wrapper handles auth failures gracefully

## Tasks

- [x] Add token revocation detection and error resilience to `claudeOauthService.ts`:
  - Add `isClaudeOauthAuthRevoked(error)` helper to `claudeOauthAuth.ts` — detect `invalid_grant`, `revoked`, or `unauthorized` responses from Anthropic's token endpoint
  - In the refresh flow: if refresh fails with revocation, clear stored auth and return a descriptive error suggesting the user re-authenticate
  - In `getValidAuth()`: wrap the entire flow in try-catch so unexpected errors (network failures, malformed stored data) never throw — return `Err(...)` instead
  - In the fetch wrapper (providerModelFactory): if `getValidAuth()` returns an error during a request, surface it as a clear error message rather than silently failing with a bad token

- [x] Ensure proper cleanup and lifecycle management:
  - Verify `OAuthFlowManager.shutdownAll()` is called on app exit for Claude flows (check how Codex flows are cleaned up in `serviceContainer.ts` or app shutdown handlers)
  - Ensure the loopback HTTP server (port 1456) is properly closed after token exchange completes or on timeout
  - Add the Claude OAuth service to any shutdown/dispose handlers that exist for other OAuth services
  - *(Already implemented: `claudeOauthService.dispose()` calls `desktopFlows.shutdownAll()` + device flow cleanup; `serviceContainer.dispose()` line 625 and CLI `run.ts` line 1120 both call it; loopback server closed via `OAuthFlowManager.finish()` → `closeServer()`)*

- [x] Handle the "OAuth connected but token fully expired and unrefreshable" case:
  - If both access and refresh tokens are invalid, the UI should show a "Session expired — please reconnect" state rather than silently failing
  - Add an ORPC method or use existing config watching to let the frontend detect when Claude OAuth has become invalid
  - Search for how Codex handles this (likely the UI checks `codexOauth` in provider config and `getValidAuth` status)
  - *(Implemented: `claudeOauth.checkAuth` ORPC method calls `getValidAuth()` and maps to `Result<void, string>`. Frontend calls it on mount when `claudeOauthIsConnected` is true; on error, shows "Session expired — please reconnect" in destructive color. Codex has no equivalent — this is a Claude OAuth improvement.)*

- [x] Review and align with existing provider patterns:
  - Search `src/common/constants/providers.ts` for the Anthropic provider definition — ensure `requiresApiKey` or similar flags are updated to reflect that API key is optional when OAuth is available
  - Check if there's a provider status/health check mechanism that should report Claude OAuth status
  - Ensure the known models list in `knownModels.ts` doesn't need updates (all Anthropic models should be OAuth-allowed)
  - *(Reviewed: `requiresApiKey: true` stays correct — matches Codex OAuth pattern where the flag stays true but OAuth is handled as a special credential path. Added `parseClaudeOauthAuth` check to `hasAnyConfiguredProvider()` in `providerRequirements.ts` so CLI bootstrap recognizes Claude OAuth-only setups as valid. `providerService.ts` already marks anthropic as `isConfigured` when `claudeOauthSet` is true (line 261). `knownModels.ts` lists `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5` — exactly matching `CLAUDE_OAUTH_ALLOWED_MODELS`. No health check mechanism exists beyond per-request `getValidAuth()` and the `checkAuth` ORPC method.)*

- [ ] Final compilation and full test suite:
  - Run `make typecheck` — zero errors
  - Run `make lint-fix` — clean output
  - Run `make test` — all tests pass (including existing tests, to verify no regressions)
  - Run `make build` — clean production build

- [ ] End-to-end code review pass:
  - Read through all new files created in this effort:
    - `src/common/constants/claudeOAuth.ts`
    - `src/node/utils/claudeOauthAuth.ts`
    - `src/node/services/claudeOauthService.ts`
    - All modified files (providersConfig, router, context, serviceContainer, providerModelFactory, ProvidersSection)
  - Verify consistency with Codex OAuth patterns
  - Check for any hardcoded values that should be constants
  - Confirm no `as any` casts, no security issues (XSS, injection), no direct `localStorage` calls
  - Verify all new code follows project conventions from CLAUDE.md
