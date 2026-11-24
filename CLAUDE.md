# AI Agent Guidelines for nextjs-auth0

This document provides context and guidelines for AI coding assistants working with the nextjs-auth0 codebase.

> **Agent skills:** for task-specific, version-pinned guidance read [`skills/SKILL.md`](skills/SKILL.md) (hub) and its sub-skills (e.g. `skills/mfa/SKILL.md`). These ship inside the published package, so they are also present under `node_modules/@auth0/nextjs-auth0/skills/` in a consuming app.

## Project Overview

**`@auth0/nextjs-auth0`** is the Auth0 authentication SDK for Next.js (App Router + Pages Router).

- **Language:** TypeScript 5.9 (strict), ESM (`"type": "module"`, `module: NodeNext`, target ES2021)
- **Tech Stack:** Next.js (peer, dev 15.5.x), React 18/19 (peer), `oauth4webapi` ^3.8, `openid-client` ^6.8, `jose` ^6, `swr` ^2, Vitest 4, MSW 2, Playwright
- **Package Manager:** pnpm (CI uses pnpm 11)
- **Minimum Platform Version:** SDK runtime Node.js 20 LTS+; development needs Node.js 22+ (pnpm 11, as in CI); Next.js ^14.2.35 || ~15.0.7 || ~15.1.11 || ~15.2.8 || ~15.3.8 || ~15.4.10 || ~15.5.9 || ^16.0.10

---

## Commands

> Copy-paste ready. These match CI (`.github/workflows/test.yml`) and `package.json`.

```bash
# Install
pnpm install --frozen-lockfile

# Build
pnpm run build

# Run all unit tests
pnpm test:unit

# Run tests with coverage (CI)
pnpm run test:coverage

# Lint + typecheck (src and tests) (CI)
pnpm run lint

# Auto-fix lint/format
pnpm run lint:fix

# Generate API docs (typedoc -> docs/)
pnpm run docs
```

### Additional Commands

```bash
pnpm run build:watch     # tsc -w
pnpm test:e2e            # Playwright; needs TEST_USER_PASSWORD, run separately from CI
pnpm run prepack         # build, used before publish
```

Pre-commit hook (`lefthook.yml`) runs `pnpm run lint:fix`. Full local validation: `pnpm run test:coverage && pnpm run prepack && pnpm run lint:fix`.

---

## Testing

- **Framework:** Vitest ^4 (`vitest.config.mts`), jsdom for client tests, `@testing-library/react`
- **Test Location:** co-located `*.test.ts(x)` in `src/`; `tests/` for extras; `e2e/` for Playwright
- **Coverage Tool:** `@vitest/coverage-v8` over `src/**/*`, uploaded to Codecov in CI
- **Coverage Threshold:** none enforced in config; do not reduce coverage

### Running Tests

```bash
# All unit tests
pnpm test:unit

# A single test file
pnpm exec vitest --run src/server/client.test.ts

# Watch mode
pnpm exec vitest
```

### Testing Conventions

- `*.test.ts` unit tests sit next to the source; `*.flow.test.ts` are black-box flow tests; `*.msw.test.ts` use MSW.
- Flow tests: MSW mocks HTTP only, the SDK is called normally; no other mocks unless required.
- Use `generateSessionCookie` from `@auth0/nextjs-auth0/testing` to set up sessions.
- E2E (`e2e/`) runs separately and requires credentials.

See [references/testing.md](references/testing.md).

---

## Project Structure

```
src/
├── client/           # React hooks, Auth0Provider, client getAccessToken (+ mfa, passkey, passwordless)
├── server/           # Auth0Client (public API), AuthClient (internal)
│   ├── session/      # Stateless (cookie) + Stateful (external store)
│   ├── helpers/      # withPageAuthRequired, withApiAuthRequired
│   ├── client.ts     # Auth0Client - main public class
│   └── auth-client.ts # Internal route handling + OAuth flows
├── errors/           # SdkError hierarchy (catch by error.code)
├── types/            # SessionData, User, TokenSet, AuthorizationParameters
├── utils/            # Internal: dpop, paths, scopes, urls
└── testing/          # generateSessionCookie
skills/               # Agent skills shipped in the package (SKILL.md hub + mfa, organizations, passkeys)
guides/               # Feature guides (mfa, passkeys, my-account, experiment-center)
examples/             # Example apps (own package.json each; excluded from vitest)
e2e/  tests/          # Playwright and extra tests
docs/                 # Generated typedoc output - do not edit by hand
```

### Key Files

| File | Purpose |
|------|---------|
| [src/server/client.ts](src/server/client.ts) | `Auth0Client` implementation |
| [src/server/auth-client.ts](src/server/auth-client.ts) | Internal OAuth/route handling |
| [src/client/hooks/use-user.ts](src/client/hooks/use-user.ts) | `useUser` hook |
| [src/errors/index.ts](src/errors/index.ts) | All error class definitions |
| [EXAMPLES.md](EXAMPLES.md) | Usage patterns and code samples |

Public exports (`.`, `/server`, `/errors`, `/types`, `/testing`), data flows (login, logout, getSession, getAccessToken, useUser, stateful session), MRRT, DPoP and hooks: [references/architecture.md](references/architecture.md).

---

## Code Style

Enforced by `eslint.config.mjs` (typescript-eslint, react, prettier) and `prettier.config.mjs`.

### Naming Conventions

- Files: kebab-case (`auth-client.ts`); a few legacy utils are camelCase (`dpopUtils.ts`)
- Classes/types: PascalCase; functions/variables: camelCase; error `code` values: snake_case
- Relative imports use the `.js` extension (NodeNext): `import { Auth0Client } from "../client.js"`
- Double quotes, semicolons, 2-space indent, no trailing commas, LF; imports sorted by `@ianvs/prettier-plugin-sort-imports`
- `no-console` warns except `error`/`info`/`warn`; unused vars error unless prefixed `_`

**✅ Good:**

```ts
import { User } from "../../types/index.js";
import { Auth0Client } from "../client.js";

/** @category Route Protection */
export type GetServerSidePropsResultWithSession<P = any> =
  GetServerSidePropsResult<P & { user: User }>;
```

**❌ Bad:**

```ts
import { Auth0Client } from '../client'   // no .js extension, single quotes, no semicolon
import { AuthClient } from "../../server/auth-client.js"  // internal class leaked into public code
```

### Patterns Used in This Project

- Single `Auth0Client` instance per app; internal `AuthClient` handles routes and OAuth flows.
- Errors extend `SdkError` and carry a `code`; consumers catch by `error.code`. Details: [references/errors.md](references/errors.md).
- Public API items carry TypeDoc `@category` tags.

---

## Git Workflow

### Branch Naming

No enforced convention. Release PRs are titled `Release vX.Y.Z`. PRs target `main` (also `v4`, `beta` are CI-checked).

### Commit Messages

Conventional Commits with an optional PR number: `feat(passkey): ...`, `fix(mfa): ...`, `chore(deps): ...`, `docs: ...`, `ci: ...`.

### Pull Requests

- Use `.github/PULL_REQUEST_TEMPLATE.Md`: checklist (tests covered, docs added) plus Changes / References / Testing sections. Incomplete checklists get PRs closed.
- Required CI: Build and Test (`test.yml`: build, coverage, lint), CodeQL, Snyk. Code owners: `@auth0/project-dx-sdks-engineer-codeowner`.

---

## Boundaries

### ✅ Always Do

- Run `pnpm run test:coverage` and `pnpm run lint` before committing
- Follow existing code style, `.js` import extensions, and naming conventions
- Add unit tests for new functionality (flow tests via MSW for HTTP behavior)
- Use typed errors from the `SdkError` hierarchy and catch by `error.code`
- Leave `CHANGELOG.md` and version bumps to the release PR (see Release Process)
- Update `README.md` and `EXAMPLES.md` in the same PR when changing the public API, configuration options, or supported integration patterns
- Update the relevant `skills/**/SKILL.md` or `guides/*.md` when changing the behaviour they describe

### ⚠️ Ask First

- Adding new dependencies
- Modifying public API signatures or the `exports` map in `package.json`
- Changes to CI/CD configuration (`.github/workflows`, `.github/actions`)
- Changes to session/cookie format, encryption, or stateful store contract
- Modifying security-related code (token handling, DPoP, mTLS, cookie encryption)
- Changing peer dependency ranges

### 🚫 Never Do

- Commit secrets, API keys, or tokens (including `.env*` files)
- Modify generated files by hand: `docs/` (typedoc output), `pnpm-lock.yaml`
- Edit build output or vendor dirs: `dist/`, `node_modules/`, `coverage/`
- Remove or skip failing tests without fixing them
- Break backward compatibility without explicit approval
- Log access tokens, refresh tokens, ID tokens, or client secrets
- Import from internal paths (e.g. `src/server/auth-client.ts`) in consumer-facing code or examples
- Use `instanceof` for SDK error handling (use `error.code`)
- Store sensitive data in client-accessible session fields
- Call `getAccessToken()` without checking the user is authenticated first

---

## Security Considerations

- OAuth 2.0 / OIDC authorization-code flow via `openid-client` / `oauth4webapi`; transactions stored in `TransactionStore`.
- Sessions are encrypted cookies (`AUTH0_SECRET`: 32-byte hex string, generate with `openssl rand -hex 32`; HKDF via `@panva/hkdf`, JWE via `jose`) or a custom stateful `SessionDataStore`.
- Optional DPoP (`useDPoP: true` + `dpopKeyPair`) and mTLS support bind tokens to the client.
- Secrets are supplied via environment variables (`AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`) or the `Auth0Client` `clientSecret` / `secret` options (e.g. loaded from a secret manager); never hardcode or log them. `OAuth2Error` may contain user input - do not render it unescaped.
- Scanners in CI: CodeQL, Snyk, Release-time `rl-secure` scan. Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## Dependencies

### Core Dependencies

`@edge-runtime/cookies` ^5.0.1, `@panva/hkdf` ^1.2.1, `jose` ^6.0.11, `oauth4webapi` ^3.8.2, `openid-client` ^6.8.0, `swr` ^2.2.5. Peers: `next`, `react`, `react-dom` (ranges in [references/configuration.md](references/configuration.md)).

### Test Dependencies

`vitest` ^4.1, `@vitest/coverage-v8`, `msw` ^2.7, `jsdom` ^26, `@testing-library/react` ^16, `@playwright/test`.

Env vars (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_SECRET`, `APP_BASE_URL`, `AUTH0_COOKIE_*`, `AUTH0_DPOP_*`, `NEXT_PUBLIC_*_ROUTE`): [references/configuration.md](references/configuration.md).

---

## Release Process

- Version lives in `package.json` and `.version`; changelog is `CHANGELOG.md` (generated per release with PR links).
- Merging a `Release vX.Y.Z` PR triggers `.github/workflows/release.yml`: `rl-secure` scan, then `npm-release.yml` (version from `.version`, tag check, npm publish with provenance, GitHub release). Prerelease tags are guarded for the `beta` branch.
- Do not bump versions or edit `CHANGELOG.md` in feature PRs.

---

## Common Pitfalls

- Missing `.js` extension on relative imports breaks the NodeNext build.
- `pnpm run lint` typechecks both `tsconfig.json` and `tsconfig.test.json`; test-only type errors fail lint.
- `examples/` are separate packages; install with `pnpm run install:examples`, they are not covered by root tests.
- Next.js version differences (middleware vs. proxy, App vs. Pages Router): check both when changing request/cookie handling.
- `docs/` is typedoc output - regenerate with `pnpm run docs`, never edit.

---

## External References

- [README.md](README.md), [EXAMPLES.md](EXAMPLES.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md)
- Migration guides: [V4](V4_MIGRATION_GUIDE.md), [V3](V3_MIGRATION_GUIDE.md), [V2](V2_MIGRATION_GUIDE.md), [V1](V1_MIGRATION_GUIDE.md)
- [API reference](https://auth0.github.io/nextjs-auth0/), [Auth0 Next.js quickstart](https://auth0.com/docs/quickstart/webapp/nextjs)
- Agent skills: [skills/SKILL.md](skills/SKILL.md); deeper notes in [references/](references/)

---

## Docs Update Rules

> Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR.

### Tracked Docs

| Doc | Status | Covers |
|-----|--------|--------|
| `README.md` | ⚠️ stale | Install, env vars, setup, links |
| `EXAMPLES.md` | ✅ current | Usage patterns for each feature |

### When You Change Code, Update These Docs

| Code change | Update |
|-------------|--------|
| `Auth0Client` options / config (`src/server/client.ts`) | `README.md` config section, `EXAMPLES.md`, `references/configuration.md` |
| New/renamed public export (`src/*/index.ts`, `package.json` `exports`) | `EXAMPLES.md`, `references/architecture.md` |
| New/changed error class or `code` (`src/errors/`) | `references/errors.md`, `EXAMPLES.md` |
| Env vars or install steps | `README.md`, `references/configuration.md` |
| MFA / organizations / passkeys behaviour | `skills/*/SKILL.md`, `guides/*.md` |
| Hooks, session, DPoP, MRRT behaviour | `EXAMPLES.md`, `references/architecture.md` |

### Drift Status

- `README.md`: link `./docs/anonymous-sessions.md` does not resolve (no such file on `main`). Fix the link or add the doc.
- `EXAMPLES.md`: no stale internal links found.

> If any doc is marked ⚠️ stale or ❌ missing, fix it **in the same PR** as the code change — do not defer.
