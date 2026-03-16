# Phase 04: Tests for Claude OAuth

This phase adds comprehensive tests for the Claude OAuth service, auth utilities, constants, and provider factory integration. Tests ensure token parsing, expiry, refresh, OAuth flows, and factory routing all work correctly.

## Important Context

Follow the existing test patterns exactly:
- `src/node/services/codexOauthService.test.ts` — template for service tests (uses mock Config, ProviderService, WindowService)
- `src/node/utils/codexOauthAuth.test.ts` — template for auth utility tests (if it exists; otherwise check test patterns in `src/node/utils/`)
- The project uses `bun test` as the test runner
- Run tests with `make test` or `bun test <specific-file>`

**Important project rules:**
- No tautological tests — don't just assert constant values match themselves
- Test behavioral branches: token expiry logic, refresh paths, error cases, flow state transitions
- Use real instances where possible (per CLAUDE.md: "Always use a real instance" for services with disk I/O)
- For OAuth service tests, mocking is appropriate since it involves network calls and browser opens

## Tasks

- [x] Create `src/node/utils/claudeOauthAuth.test.ts` — auth utility tests:
  - Test `parseClaudeOauthAuth` with:
    - Valid auth object → returns typed `ClaudeOauthAuth`
    - Missing required fields (access, refresh, expires) → returns null
    - Wrong `type` field → returns null
    - Extra fields are preserved (passthrough)
    - Non-object input (string, null, undefined, number) → returns null
  - Test `isClaudeOauthAuthExpired` with:
    - Token expiring in the future → not expired
    - Token already expired → expired
    - Token within skew window (default 30s) → expired
    - Custom skew override works
    - Custom nowMs override works

- [x] Create `src/common/constants/claudeOAuth.test.ts` — constants and helper tests:
  - Test `buildClaudeAuthorizeUrl` produces correct URL with all required params (response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method)
  - Test `buildClaudeTokenExchangeBody` produces correct URLSearchParams
  - Test `buildClaudeRefreshBody` produces correct URLSearchParams
  - Test `isClaudeOauthAllowedModelId` with known allowed model IDs and non-allowed IDs
  - Test `isClaudeOauthRequiredModelId` returns false for all models (empty set currently)
  - Test model ID normalization (with and without `anthropic:` prefix)

- [x] Create `src/node/services/claudeOauthService.test.ts` — service tests:
  - Mirror the test structure from `codexOauthService.test.ts`
  - Create mock helpers: `createMockConfig`, `createMockProviderService`, `createMockWindowService`
  - Test `getValidAuth()`:
    - Returns stored auth when not expired
    - Triggers refresh when expired, returns new auth
    - Returns error when no auth stored
    - Mutex prevents concurrent refreshes (second caller gets already-refreshed token)
  - Test `startDesktopFlow()`:
    - Returns flowId and authorizeUrl
    - AuthorizeUrl contains correct params
  - Test `disconnect()`:
    - Clears stored auth
    - Subsequent `getValidAuth()` returns error
  - Test token exchange:
    - Valid code exchange stores auth correctly
    - Invalid response returns error
  - Test refresh flow:
    - Successful refresh updates stored auth
    - Failed refresh (invalid_grant) returns appropriate error

- [x] Run all new tests and fix any failures:
  - Run `bun test src/node/utils/claudeOauthAuth.test.ts`
  - Run `bun test src/common/constants/claudeOAuth.test.ts`
  - Run `bun test src/node/services/claudeOauthService.test.ts`
  - Fix any failures before proceeding
  - Run `make typecheck` to confirm no type regressions
