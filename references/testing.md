# Testing Details

## Unit tests
- Framework: Vitest (`vitest.config.mts`), co-located `*.test.ts` in `src/`
- Run: `pnpm test:unit`

## Flow tests (`*.flow.test.ts`)
Black-box tests. MSW mocks HTTP only, the SDK is called normally. No other mocks unless required.

## File conventions

| Pattern | Purpose |
|---------|---------|
| `*.test.ts` | Unit test, co-located with source |
| `*.flow.test.ts` | Integration/flow tests |
| `*.msw.test.ts` | Tests using MSW mocking |

## E2E
Playwright (`playwright.config.ts`, `e2e/`). Runs separately and needs credentials (`TEST_USER_PASSWORD`).

## CI/validation pipeline

```bash
pnpm run test:coverage && pnpm run prepack && pnpm run lint:fix
```
