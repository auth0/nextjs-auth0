# Test Coverage Matrix

This example ships a tiered test suite. The browser (Playwright) tier is intentionally a thin slice over the SDK's unit and integration coverage, not a replacement for it.

## Coverage by Tier

| Behavior                        | Unit (src/)                       | Live (Tier1)                   | MSW (Tier2)            | Offline e2e (mock)      | Browser e2e         | Notes                                                                             |
| ------------------------------- | --------------------------------- | ------------------------------ | ---------------------- | ----------------------- | ------------------- | --------------------------------------------------------------------------------- |
| Create success                  | `POST /api/anon/create` (T1.1)    | L1 (happy path)                | T2.1 (mock AS success) | O1, O2                  | —                   | O1/O2 prove example wiring + SDK persist; unit + live prove full invariant        |
| Create errors (AS rejects)      | T1.2 (mock tenant error)          | L2 (live tenant unreachable)   | T2.2 (mock AS 500)     | O9-O13                  | —                   | O9-O13 cover 403/400/500; unit + MSW prove SDK error-mapping                      |
| Get/read                        | T1.3 (unit flow.test)             | L3 (live GET after create)     | —                      | O1, O3                  | —                   | O1/O3 prove example wiring + SDK decrypt; unit + live prove full invariant        |
| Renew (silent)                  | T1.4-1.6 (unit + integration)     | L4 (live renewal)              | T2.3 (mock AS renewal) | O15                     | —                   | O15 proves example wiring + SDK renew; unit + live prove full invariant           |
| Logout                          | T1.7 (unit flow.test)             | L5 (live logout)               | —                      | O-logout                | L11 (logout UI)     | O-logout + L11 exercise UI reset + navigation; unit proves server invariant       |
| SEC-1 strip+inject              | flow.test.ts:451-490, :561        | —                              | —                      | —                       | L9a/L9b/L9c (strip) | L9 proves end-to-end HTTP layer; unit proves server logic                         |
| SEC-1 bind/tamper               | flow.test.ts:565-642              | —                              | —                      | —                       | —                   | Unit coverage sufficient (callback tamper)                                        |
| Callback link (happy)           | flow.test.ts (unit callback flow) | —                              | —                      | —                       | L10a (live link)    | L10a live-gated; unit proves server logic                                         |
| Callback link (tamper negative) | flow.test.ts:565-642              | —                              | —                      | —                       | —                   | Unit proves anonymousSessionLinked=false on digest mismatch                       |
| Cookie chunking >4KB            | cookies.test.ts (unit)            | —                              | —                      | O16 (single-cookie doc) | —                   | O16 asserts single-cookie for typical payloads; unit proves chunk logic           |
| Metadata set-once               | T1.8 (unit, POST with metadata)   | L6 (live set-once enforcement) | —                      | O17                     | —                   | O17 proves metadata retained across renewal; unit + live prove set-once invariant |
| Metadata 1KB cap                | T1.9 (unit, POST with oversized)  | —                              | —                      | O14                     | —                   | O14 proves client-side cap; unit coverage sufficient                              |
| Hook loading/error/data states  | —                                 | —                              | —                      | O3, O4, O5, O7          | L12 (error banner)  | O3/O4/O5/O7 + L12 prove loading/error/data states; L11 exercises data state       |
| Error banner UI                 | —                                 | —                              | —                      | O9                      | L12 (error banner)  | O9 + L12 prove error banner rendering                                             |
| Logout UI                       | —                                 | —                              | —                      | O-logout                | L11 (logout UI)     | O-logout + L11 prove logout UI flow                                               |

## Offline Mock Tier

The offline tier (17 tests in `tests/e2e/offline/`) runs against a mock Auth0 tenant at the `customFetch` layer (`lib/mock/anon-mock-fetch.ts`). The mock intercepts `POST /anonymous/token` and `POST /anonymous/logout` requests and returns configurable responses (success, expired, 403/400/500 errors), controlled via the scenario route `app/api/test/mock-scenario`. The SDK's real encrypt/persist/decrypt/renew logic executes normally — only the network hop is faked.

**What it tests:**

- Example wiring (create/get/renew/logout routes, error-mapping, UI state)
- SDK read/persist/renew/error-handling paths
- Deterministic error scenarios (feature_not_enabled, unauthorized_client, invalid_target, invalid_scope, server_error, metadata_too_large)

**What it does NOT test:**

- The actual `/anonymous/token` wire contract (request/response shape, server-side validation, token issuance)
- Live tenant configuration (client grants, `anonymous_sessions.active`, audience setup)
- Access token signature verification, aud/iss/exp claims validation, scope enforcement, and session_expires_in handling — the mock uses an unsigned synthetic JWT and omits those fields; only the live Tier1 specs prove the real /anonymous/token wire contract

Run: `pnpm test:e2e:offline`. Needs no tenant credentials. Boots a test server on `:3001` with `E2E_ANON_MOCK=1`.

**Coverage:** O1-O8 (session lifecycle), O9-O14 (error paths), O15-O17 (renewal, chunking constraint, metadata set-once). See matrix above for cross-tier coverage. The live Tier1 specs (L1-L8, L9b, L10a) remain the definitive verification of the Auth0 wire contract.

## Known Gaps at the Browser Tier (By Design)

The following behaviors are NOT covered at the live browser (Playwright) tier, but are proven at lower test tiers:

- **Cookie-tamper negative (SEC-1 bind)** — Covered by unit test `src/server/anonymous-session.flow.test.ts:565-642`, which asserts `anonymousSessionLinked=false` on digest mismatch. A browser test would require a live tenant and manual cookie manipulation; the unit test already proves the invariant.

- **Cookie chunking >4KB** — Covered by unit test `src/cookies.test.ts` (chunk logic). Offline test O16 documents that typical payloads remain single-cookie and that >4KB is unreachable through the public create path (1KB metadata cap). The SDK's cookie-chunking logic is deterministic and does not require live browser validation.

- **Live callback link (negative case)** — L10a proves the happy path (anonymousSessionLinked=true). The tamper negative case is covered by unit test `src/server/anonymous-session.flow.test.ts:565-642`.

## Default Run vs Full Run

**Offline tier (`pnpm test:e2e:offline`):** Runs fully unconditionally (17/17 specs). No credentials required.

**Live tier (`pnpm test:e2e`):** Without tenant credentials (`AUTH0_DOMAIN`, `AUTH0_CLIENT_SECRET`, `AUTH0_CLIENT_ID`):

- **Run unconditionally:** L9a, L9c (strip), L11 (logout UI), L12 (error banner)
- **Skip (gated on live tenant):** L9b (strip with legit cookie), L10a (callback link happy)

When reading green test output, do NOT interpret it as exhaustive security coverage. The browser tier is a thin slice. The SDK's unit and integration tests provide the bulk of coverage.
