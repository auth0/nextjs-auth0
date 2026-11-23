# Error Handling

Base class: `SdkError` (`src/errors/sdk-error.ts`) with an abstract `code: string` property.

| Error Class | Code | Cause |
|-------------|------|-------|
| `AccessTokenError` | `access_token_error` | Token fetch/refresh failure |
| `AuthorizationError` | `authorization_error` | OAuth authorize failure |
| `InvalidConfigurationError` | `invalid_configuration` | Bad SDK config |
| `DiscoveryError` | `discovery_error` | OIDC discovery failed |
| `OAuth2Error` | varies | Auth0 callback error (may contain user input) |

**Pattern:** catch by `error.code`, not `instanceof`.

```ts
try {
  await auth0.getAccessToken();
} catch (e) {
  if ((e as { code?: string }).code === "access_token_error") {
    // handle
  }
}
```

All error definitions are exported from `src/errors/index.ts` (public path `@auth0/nextjs-auth0/errors`).
