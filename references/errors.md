# Error Handling

Base class: `SdkError` (`src/errors/sdk-error.ts`) with an abstract `code: string` property.

| Error Class | Code | Cause |
|-------------|------|-------|
| `AccessTokenError` | `missing_session`, `missing_refresh_token`, `failed_to_refresh_token`, `session_expired` (`AccessTokenErrorCode`) | Token fetch/refresh failure |
| `AuthorizationError` | `authorization_error` | OAuth authorize failure |
| `InvalidConfigurationError` | `invalid_configuration` | Bad SDK config |
| `DiscoveryError` | `discovery_error` | OIDC discovery failed |
| `OAuth2Error` | varies | Auth0 callback error (may contain user input) |

**Pattern:** catch by `error.code`, not `instanceof`.

```ts
import { AccessTokenErrorCode } from "@auth0/nextjs-auth0/errors";

try {
  await auth0.getAccessToken();
} catch (e) {
  if ((e as { code?: string }).code === AccessTokenErrorCode.MISSING_SESSION) {
    // handle
  }
}
```

All error definitions are exported from `src/errors/index.ts` (public path `@auth0/nextjs-auth0/errors`).
