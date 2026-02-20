![Auth0 Next.js SDK Banner](https://cdn.auth0.com/website/sdks/banners/nextjs-auth0-banner.png)

The Auth0 Next.js SDK is a library for implementing user authentication in Next.js applications.

[![Auth0 Next.js SDK Release](https://img.shields.io/npm/v/@auth0/nextjs-auth0)](https://www.npmjs.com/package/@auth0/nextjs-auth0)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/nextjs-auth0)
![Auth0 Next.js SDK Downloads](https://img.shields.io/npm/dw/@auth0/nextjs-auth0)
[![Auth0 Next.js SDK License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](https://auth0.github.io/nextjs-auth0/) - 💬 [Feedback](#feedback)

## Documentation

- [QuickStart](https://auth0.com/docs/quickstart/webapp/nextjs) - our guide for adding Auth0 to your Next.js app.
- [Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md) - lots of examples for your different use cases.
- [Security](https://github.com/auth0/nextjs-auth0/blob/main/SECURITY.md) - Some important security notices that you should check.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/nextjs-auth0
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Add the environment variables

Add the following environment variables to your `.env.local` file:

```env
AUTH0_DOMAIN=
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=
AUTH0_SECRET=
APP_BASE_URL= # optional for dynamic preview environments
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.

The `AUTH0_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 32
```

The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.
If you omit it, the SDK will infer the base URL from the incoming request host at runtime.

> [!IMPORTANT]  
> You will need to register the following URLs in your Auth0 Application via the [Auth0 Dashboard](https://manage.auth0.com):
>
> - Add `http://localhost:3000/auth/callback` to the list of **Allowed Callback URLs**
> - Add `http://localhost:3000` to the list of **Allowed Logout URLs**
>
> When using dynamic hosts (preview environments), ensure the resulting callback and logout URLs are registered in your Auth0 application.

#### Dynamic base URLs (Preview deployments)

For preview environments (`Vercel`, `Netlify`), you can omit `APP_BASE_URL` and let the SDK infer the base URL from the incoming request host at runtime. This keeps dynamic preview URLs working without extra configuration.

If you know the base URL at startup (for example, a stable production domain), set `appBaseUrl` or `APP_BASE_URL` to a single absolute URL. Comma-separated values are not supported.

Because the Host header is untrusted input, Auth0's Allowed Callback URLs are the safety net in this mode: if the inferred host is not registered, Auth0 rejects the authorize request.

Example (dynamic):

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client();
```

Example (static):

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  appBaseUrl: "https://app.example.com"
});
```

> [!NOTE]  
> When relying on dynamic base URLs in production, the SDK enforces secure cookies. If you explicitly set `AUTH0_COOKIE_SECURE=false`, `session.cookie.secure=false`, or `transactionCookie.secure=false`, the SDK throws `InvalidConfigurationError`.

### 3. Create the Auth0 SDK client

Create an instance of the Auth0 client. This instance will be imported and used in anywhere you need access to the authentication methods on the server.

Add the following contents to a file named `lib/auth0.ts`:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client();
```

> [!NOTE]
> The Auth0Client automatically uses safe defaults to manage authentication cookies. For advanced use cases, you can customize transaction cookie behavior by providing your own configuration. See [Transaction Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#transaction-cookie-configuration) for details.

### 4. Add the authentication middleware
Authentication requests in Next.js are intercepted at the network boundary using a middleware or proxy file.  
Follow the setup below depending on your Next.js version.

#### 🟦 On Next.js 15

Create a `middleware.ts` file in the root of your project:

```ts
import type { NextRequest } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"
  ]
};
```

> [!NOTE]  
> If you're using a `src/` directory, the `middleware.ts` file must be created inside the `src/` directory.


#### 🟨 On Next.js 16
Next.js 16 introduces a new convention called proxy.ts, replacing middleware.ts.
This change better represents the network interception boundary and unifies request handling
for both the Edge and Node runtimes.

Create a proxy.ts file in the root of your project (Or rename your existing middleware.ts to proxy.ts):
```ts
import { auth0 } from "./lib/auth0";

export async function proxy(request: Request) { // Note that proxy uses the standard Request type
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"
  ]
};
```
> [!IMPORTANT]  
> Starting with **Next.js 16**, the recommended file for handling authentication boundaries is **`proxy.ts`**. You can still continue using **`middleware.ts`** for backward compatibility, it will work under the **Edge runtime** in Next.js 16. However, it is **deprecated** for the Node runtime and will be removed in a future release.
>
> The new proxy layer also executes slightly earlier in the routing pipeline, so make sure your matcher patterns do not conflict with other proxy or middleware routes.  
>
> Additionally, the Edge runtime now applies stricter header and cookie validation,  
> so avoid setting non-string cookie values or invalid header formats.  

> [!IMPORTANT]
> This broad middleware matcher is essential for rolling sessions and security features. For scenarios when rolling sessions are disabled, see [Session Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for alternative approaches.

You can now begin to authenticate your users by redirecting them to your application's `/auth/login` route:

```tsx
import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export default async function Home() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <a href="/auth/login?screen_hint=signup">Sign up</a>
        <a href="/auth/login">Log in</a>
      </main>
    );
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}!</h1>
    </main>
  );
}
```

> [!IMPORTANT]  
> You must use `<a>` tags instead of the `<Link>` component to ensure that the routing is not done client-side as that may result in some unexpected behavior.

## Customizing the client

You can customize the client by using the options below:

| Option                      | Type                      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| domain                      | `string`                  | The Auth0 domain for the tenant (e.g.: `example.us.auth0.com` or `https://example.us.auth0.com`). If it's not specified, it will be loaded from the `AUTH0_DOMAIN` environment variable.                                                                                                                                                                                                                                                                                                                                                                                            |
| clientId                    | `string`                  | The Auth0 client ID. If it's not specified, it will be loaded from the `AUTH0_CLIENT_ID` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| clientSecret                | `string`                  | The Auth0 client secret. If it's not specified, it will be loaded from the `AUTH0_CLIENT_SECRET` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| authorizationParameters     | `AuthorizationParameters` | The authorization parameters to pass to the `/authorize` endpoint. See [Passing authorization parameters](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#passing-authorization-parameters) for more details.                                                                                                                                                                                                                                                                                                                                                           |
| clientAssertionSigningKey   | `string` or `CryptoKey`   | Private key for use with `private_key_jwt` clients. This can also be specified via the `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| clientAssertionSigningAlg   | `string`                  | The algorithm used to sign the client assertion JWT. This can also be provided via the `AUTH0_CLIENT_ASSERTION_SIGNING_ALG` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| appBaseUrl                  | `string`                  | The URL of your application (e.g.: `http://localhost:3000`). If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable or inferred from the request host at runtime. |
| logoutStrategy              | `"auto" \| "oidc" \| "v2"` | Strategy for logout endpoint selection. `"auto"` (default) uses OIDC logout when available, falls back to `/v2/logout`. `"oidc"` always uses OIDC logout. `"v2"` always uses `/v2/logout` endpoint which supports wildcard URLs. See [Configuring logout strategy](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#configuring-logout-strategy) for details. |
| includeIdTokenHintInOIDCLogoutUrl | `boolean`            | Configure whether to include `id_token_hint` in OIDC logout URLs for privacy. Defaults to `true` (recommended). When `false`, excludes PII from logout URLs but reduces DoS protection. See [OIDC logout privacy configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oidc-logout-privacy-configuration) for details. |
| secret                      | `string`                  | A 32-byte, hex-encoded secret used for encrypting cookies. If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| signInReturnToPath          | `string`                  | The path to redirect the user to after successfully authenticating. Defaults to `/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| session                     | `SessionConfiguration`    | Configure the session timeouts and whether to use rolling sessions or not. See [Session configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for additional details. Also allows configuration of cookie attributes like `domain`, `path`, `secure`, `sameSite`, and `transient`. If not specified, these can be configured using `AUTH0_COOKIE_*` environment variables. Note: `httpOnly` is always `true`. See [Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#cookie-configuration) for details. |
| enableParallelTransactions  | `boolean`                 | Enable support for multiple concurrent authentication flows by using unique transaction cookies per flow. When `true` (default), each authentication attempt gets its own transaction cookie with a unique state suffix. When `false`, uses a single shared transaction cookie, which may cause conflicts with concurrent auth attempts. See [Transaction Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#transaction-cookie-configuration) for details.                                                                                      |
| transactionCookie           | `TransactionCookieOptions` | Configure transaction cookie management for authentication flows. You can control cookie expiration and other cookie options. See [Transaction Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#transaction-cookie-configuration) for details.                                                                                                                                                                                                                                                                                                 |
| beforeSessionSaved          | `BeforeSessionSavedHook`  | A method to manipulate the session before persisting it. See [beforeSessionSaved](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#beforesessionsaved) for additional details.                                                                                                                                                                                                                                                                                                                                                                                           |
| onCallback                  | `OnCallbackHook`          | A method to handle errors or manage redirects after attempting to authenticate. See [onCallback](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oncallback) for additional details.                                                                                                                                                                                                                                                                                                                                                                                    |
| sessionStore                | `SessionStore`            | A custom session store implementation used to persist sessions to a data store. See [Database sessions](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#database-sessions) for additional details.                                                                                                                                                                                                                                                                                                                                                                      |
| pushedAuthorizationRequests | `boolean`                 | Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| routes                      | `Routes`                  | Configure the paths for the authentication routes. See [Custom routes](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#custom-routes) for additional details.                                                                                                                                                                                                                                                                                                                                                                                                           |
| allowInsecureRequests       | `boolean`                 | Allow insecure requests to be made to the authorization server. This can be useful when testing with a mock OIDC provider that does not support TLS, locally. This option can only be used when `NODE_ENV` is not set to `production`.                                                                                                                                                                                                                                                                                                                                              |
| httpTimeout                 | `number`                  | Integer value for the HTTP timeout in milliseconds for authentication requests. Defaults to `5000` milliseconds                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| enableTelemetry             | `boolean`                 | Boolean value to opt-out of sending the library name and version to your authorization server via the `Auth0-Client` header. Defaults to `true`.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| useDPoP                     | `boolean`                 | Enable DPoP (Demonstration of Proof-of-Possession) for enhanced security. When enabled, the client will generate DPoP proofs for token requests and protected resource requests. Defaults to `false`.                                                                                                                                                                                                                                                                                                                                                                               |
| dpopKeyPair                 | `DpopKeyPair`            | ES256 key pair for DPoP proof generation. If not provided, the SDK will attempt to load keys from `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY` environment variables. Keys must be in PEM format.                                                                                                                                                                                                                                                                                                                                                                           |
| dpopOptions                 | `DpopOptions`            | Configure DPoP timing validation. Supports `clockSkew` (adjust assumed current time) and `clockTolerance` (validation tolerance). Can also be configured via `AUTH0_DPOP_CLOCK_SKEW` and `AUTH0_DPOP_CLOCK_TOLERANCE` environment variables. See [DPoP Clock Validation](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#dpop-clock-validation) for details.           |

### Customizing Auth Handlers

While the authentication routes are handled automatically by the middleware, you can still customize the authentication flow through two main approaches:

- **Run custom code before auth handlers**: Intercept auth routes in your middleware to add custom logic before authentication actions
- **Run code after authentication**: Use the `onCallback` hook to add custom logic after authentication completes

Additional customization options include:
- Login parameters via query parameters or static configuration
- Session data modification using the `beforeSessionSaved` hook  
- Logout redirects using query parameters

> [!IMPORTANT]
> When customizing auth handlers, always validate user inputs (especially redirect URLs) to prevent security vulnerabilities like open redirects. Use relative URLs when possible and implement proper input sanitization.

**Quick Start**: For detailed examples and step-by-step migration patterns from v3, see [Customizing Auth Handlers](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#customizing-auth-handlers).

## Session Cookie Configuration

You can specify the following environment variables to configure the session cookie:

```env
AUTH0_COOKIE_DOMAIN=
AUTH0_COOKIE_PATH=
AUTH0_COOKIE_TRANSIENT=
AUTH0_COOKIE_SECURE=
AUTH0_COOKIE_SAME_SITE=
AUTH0_DPOP_PUBLIC_KEY=
AUTH0_DPOP_PRIVATE_KEY=
AUTH0_DPOP_CLOCK_SKEW=
AUTH0_DPOP_CLOCK_TOLERANCE=
```

### DPoP Configuration

The Auth0 Next.js SDK supports **DPoP (Demonstrating Proof-of-Possession)** for enhanced OAuth 2.0 security. DPoP binds access tokens to cryptographic key pairs, preventing token theft and replay attacks.

#### Quick Start

**Option 1: Environment Variables**
```env
# Enable DPoP and provide ES256 key pair
AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----"
AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQ...
-----END PRIVATE KEY-----"
```

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  useDPoP: true
  // Keys loaded automatically from environment variables
});
```

**Option 2: Programmatic Configuration**
```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { generateKeyPair } from "oauth4webapi";

const dpopKeyPair = await generateKeyPair("ES256");

export const auth0 = new Auth0Client({
  useDPoP: true,
  dpopKeyPair,
  dpopOptions: {
    clockTolerance: 30,  // Allow 30s clock difference
    retry: {
      delay: 100,        // 100ms retry delay
      jitter: true       // Add randomness
    }
  }
});
```

#### Making DPoP-Protected Requests

```ts
// Create a fetcher - DPoP inherited from global configuration
const fetcher = await auth0.createFetcher(req, {
  baseUrl: "https://api.example.com"
  // useDPoP is inherited from Auth0Client config
});

// Make authenticated requests with automatic DPoP proof generation
const response = await fetcher.fetchWithAuth("/protected-resource", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ data: "example" })
});
```

**DPoP Inheritance Behavior**

Fetchers created with `createFetcher` automatically inherit the global DPoP configuration from your `Auth0Client` instance.

This inheritance pattern follows the same behavior as auth0-spa-js, providing consistent developer experience across Auth0 SDKs.

For complete DPoP documentation, examples, and best practices, see [DPoP Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#dpop-demonstrating-proof-of-possession).

#### Advanced: Clock Validation Configuration

Configure timing validation for DPoP proofs to handle clock differences between client and server:

```ts
export const auth0 = new Auth0Client({
  useDPoP: true,
  dpopKeyPair: await generateKeyPair("ES256"),
  dpopOptions: {
    clockSkew: 120,      // Adjust for local clock being 2 minutes behind
    clockTolerance: 45   // Allow 45 seconds tolerance for validation
  }
});
```

Or configure via environment variables:

```env
AUTH0_DPOP_CLOCK_SKEW=300        # Clock adjustment in seconds
AUTH0_DPOP_CLOCK_TOLERANCE=90    # Tolerance in seconds
```

Respective counterparts are also available in the client configuration. See [Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#cookie-configuration) for more details.

### Proxy Handler for My Account and My Organization APIs

The SDK provides built-in proxy support for Auth0's My Account and My Organization Management APIs, enabling secure browser-initiated requests while maintaining server-side DPoP authentication and token management.

#### How It Works

The proxy handler automatically intercepts requests to `/me/*` and `/my-org/*` paths in your Next.js application and forwards them to the respective Auth0 APIs with proper authentication headers. This implements a Backend-for-Frontend (BFF) pattern where:

- Tokens and DPoP keys remain on the server
- Access tokens are automatically retrieved or refreshed
- DPoP proofs are generated for each request
- Session updates occur transparently

#### Configuration

Configure audience and scopes for the APIs:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  useDPoP: true,
  authorizationParameters: {
    audience: "urn:your-api-identifier",
    scope: {
      [`https://${process.env.AUTH0_DOMAIN}/me/`]: "profile:read profile:write",
      [`https://${process.env.AUTH0_DOMAIN}/my-org/`]: "org:read org:write"
    }
  }
});
```

#### Client-Side Usage

Make requests through the proxy paths:

```tsx
// My Account API
const response = await fetch("/me/v1/profile", {
  headers: { "scope": "profile:read" }
});

// My Organization API
const response = await fetch("/my-org/organizations", {
  headers: { "scope": "org:read" }
});
```

The `scope` header specifies the required scope. The SDK retrieves an access token with the appropriate audience and scope, then forwards the request with authentication headers.

For complete documentation, examples, and integration patterns with UI Components, see [Proxy Handler for My Account and My Organization APIs](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#proxy-handler-for-my-account-and-my-organization-apis).

## Base Path

Your Next.js application may be configured to use a base path (e.g.: `/dashboard`) — this is usually done by setting the `basePath` option in the `next.config.js` file. To configure the SDK to use the base path, you will also need to set the `NEXT_PUBLIC_BASE_PATH` environment variable which will be used when mounting the authentication routes.

For example, if the `NEXT_PUBLIC_BASE_PATH` environment variable is set to `/dashboard`, the SDK will mount the authentication routes on `/dashboard/auth/login`, `/dashboard/auth/callback`, `/dashboard/auth/profile`, etc.

> [!NOTE]
> We do not recommend using the `NEXT_PUBLIC_BASE_PATH` environment variable in conjunction with a `APP_BASE_URL` that contains a path component. If your application is configured to use a base path, you should set the `APP_BASE_URL` to the root URL of your application (e.g.: `https://example.com`) and use the `NEXT_PUBLIC_BASE_PATH` environment variable to specify the base path (e.g.: `/dashboard`).

## Configuration Validation

The SDK performs validation of required configuration options when initializing the `Auth0Client`. The following options are mandatory and must be provided either through constructor options or environment variables:

- `domain` (or `AUTH0_DOMAIN` environment variable)
- `clientId` (or `AUTH0_CLIENT_ID` environment variable)
- `secret` (or `AUTH0_SECRET` environment variable)
- Either:
  - `clientSecret` (or `AUTH0_CLIENT_SECRET` environment variable), OR
  - `clientAssertionSigningKey` (or `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable)

If any of these required options are missing, the SDK will issue a warning with a detailed message explaining which options are missing and how to provide them.

`appBaseUrl` is optional; if omitted, the SDK will infer it from the request host at runtime.

## Routes

The SDK mounts 6 routes:

1. `/auth/login`: the login route that the user will be redirected to to initiate an authentication transaction
2. `/auth/logout`: the logout route that must be added to your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be added to your Auth0 application's Allowed Callback URLs
4. `/auth/profile`: the route to check the user's session and return their attributes
5. `/auth/access-token`: the route to check the user's session and return an access token (which will be automatically refreshed if a refresh token is available)
6. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

> [!NOTE]  
> The `/auth/access-token` response includes `token`, `expires_at` (seconds since epoch), `expires_in` (TTL seconds), optional `scope`, and optional `token_type`. If you're using the client helper `getAccessToken()`, it returns only the token string by default; pass `{ includeFullResponse: true }` to get the full response payload.

> [!IMPORTANT]  
> The `/auth/access-token` route is enabled by default, but is only necessary when the access token is needed on the client-side. If this isn't something you need, you can disable this endpoint by setting `enableAccessTokenEndpoint` to `false`.

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/nextjs-auth0/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/nextjs-auth0/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/nextjs-auth0/blob/main/LICENSE"> LICENSE</a> file for more info.
</p>
