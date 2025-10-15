# Examples

- [Passing authorization parameters](#passing-authorization-parameters)
- [The `returnTo` parameter](#the-returnto-parameter)
  - [Redirecting the user after authentication](#redirecting-the-user-after-authentication)
  - [Redirecting the user after logging out](#redirecting-the-user-after-logging-out)
  - [Configuring logout strategy](#configuring-logout-strategy)
  - [Federated logout](#federated-logout)
- [Accessing the authenticated user](#accessing-the-authenticated-user)
  - [In the browser](#in-the-browser)
  - [On the server (App Router)](#on-the-server-app-router)
  - [On the server (Pages Router)](#on-the-server-pages-router)
  - [Middleware](#middleware)
- [Protecting a Server-Side Rendered (SSR) Page](#protecting-a-server-side-rendered-ssr-page)
  - [Page Router](#page-router)
  - [App Router](#app-router)
- [Protecting a Client-Side Rendered (CSR) Page](#protecting-a-client-side-rendered-csr-page)
- [Accessing the idToken](#accessing-the-idtoken)
- [Updating the session](#updating-the-session)
  - [On the server (App Router)](#on-the-server-app-router-1)
  - [On the server (Pages Router)](#on-the-server-pages-router-1)
  - [Middleware](#middleware-1)
- [Getting an access token](#getting-an-access-token)
  - [In the browser](#in-the-browser-1)
  - [On the server (App Router)](#on-the-server-app-router-2)
  - [On the server (Pages Router)](#on-the-server-pages-router-2)
  - [Middleware](#middleware-2)
  - [Multi-Resource Refresh Tokens (MRRT)](#multi-resource-refresh-tokens-mrrt)
    - [Basic Configuration](#basic-configuration)
      - [Configuring Scopes Per Audience](#configuring-scopes-per-audience)
    - [Usage Example](#usage-example)
    - [Token Management Best Practices](#token-management-best-practices)
- [DPoP (Demonstrating Proof-of-Possession)](#dpop-demonstrating-proof-of-possession)
  - [What is DPoP?](#what-is-dpop)
  - [Basic DPoP Setup](#basic-dpop-setup)
  - [Making DPoP-Protected Requests](#making-dpop-protected-requests)
  - [DPoP Configuration Options](#dpop-configuration-options)
  - [Error Handling](#error-handling)
  - [Advanced Usage](#advanced-usage)
  - [Production Considerations](#production-considerations)
  - [Troubleshooting](#troubleshooting)
- [`<Auth0Provider />`](#auth0provider-)
  - [Passing an initial user from the server](#passing-an-initial-user-from-the-server)
- [Hooks](#hooks)
  - [`beforeSessionSaved`](#beforesessionsaved)
  - [`onCallback`](#oncallback)
- [Session configuration](#session-configuration)
- [Cookie Configuration](#cookie-configuration)
- [Transaction Cookie Configuration](#transaction-cookie-configuration)
- [Database sessions](#database-sessions)
- [Back-Channel Authentication](#back-channel-authentication)
- [Connected Accounts](#connected-accounts)
- [Back-Channel Logout](#back-channel-logout)
- [Combining middleware](#combining-middleware)
- [ID Token claims and the user object](#id-token-claims-and-the-user-object)
- [Routes](#routes)
  - [Custom routes](#custom-routes)
- [Testing helpers](#testing-helpers)
  - [`generateSessionCookie`](#generatesessioncookie)
- [Programmatically starting interactive login](#programmatically-starting-interactive-login)
  - [Passing authorization parameters](#passing-authorization-parameters-1)
  - [The `returnTo` parameter](#the-returnto-parameter-1)
    - [Redirecting the user after authentication](#redirecting-the-user-after-authentication-1)
- [Getting access tokens for connections](#getting-access-tokens-for-connections)
  - [On the server (App Router)](#on-the-server-app-router-3)
  - [On the server (Pages Router)](#on-the-server-pages-router-3)
  - [Middleware](#middleware-3)
- [Customizing Auth Handlers](#customizing-auth-handlers)
  - [Run custom code before Auth Handlers](#run-custom-code-before-auth-handlers)
  - [Run code after callback](#run-code-after-callback)

## Passing authorization parameters

There are 2 ways to customize the authorization parameters that will be passed to the `/authorize` endpoint. The first option is through static configuration when instantiating the client, like so:

```ts
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email",
    audience: "urn:custom:api"
  }
});
```

The second option is through the query parameters to the `/auth/login` endpoint which allows you to specify the authorization parameters dynamically. For example, to specify an `audience`, the login URL would look like so:

```html
<a href="/auth/login?audience=urn:my-api">Login</a>
```

## The `returnTo` parameter

### Redirecting the user after authentication

The `returnTo` parameter can be appended to the login to specify where you would like to redirect the user after they have completed their authentication and have returned to your application.

For example: `/auth/login?returnTo=/dashboard` would redirect the user to the `/dashboard` route after they have authenticated.

> [!NOTE]  
> The URL specified as `returnTo` parameters must be registered in your client's **Allowed Callback URLs**.

### Redirecting the user after logging out

The `returnTo` parameter can be appended to the logout to specify where you would like to redirect the user after they have logged out.

For example: `/auth/logout?returnTo=https://example.com/some-page` would redirect the user to the `https://example.com/some-page` URL after they have logged out.

> [!NOTE]  
> The URL specified as `returnTo` parameters must be registered in your client's **Allowed Logout URLs**.

### Configuring logout strategy

By default, the SDK uses OpenID Connect's RP-Initiated Logout when available, falling back to Auth0's `/v2/logout` endpoint. You can control this behavior using the `logoutStrategy` configuration option:

```ts
export const auth0 = new Auth0Client({
  logoutStrategy: "auto" // default behavior
  // ... other config
});
```

Available strategies:

- **`"auto"`** (default): Uses OIDC logout when `end_session_endpoint` is available, falls back to `/v2/logout`
- **`"oidc"`**: Always uses OIDC RP-Initiated Logout. Returns an error if not supported by the authorization server
- **`"v2"`**: Always uses Auth0's `/v2/logout` endpoint, which supports wildcard URLs and legacy configurations

#### When to use `"v2"` strategy

The `"v2"` strategy is useful for applications that:

- Need wildcard URL support in logout redirects (e.g., `https://localhost:3000/*/about`)
- Support multiple languages or environments with dynamic URLs
- Were migrated from v3 and need to maintain existing logout URL patterns
- Have complex logout URL requirements that aren't compatible with OIDC logout

```ts
// Example: Using v2 logout for wildcard URL support
export const auth0 = new Auth0Client({
  logoutStrategy: "v2"
  // ... other config
});

// This allows logout URLs like:
// /auth/logout?returnTo=https://localhost:3000/en/dashboard
// /auth/logout?returnTo=https://localhost:3000/*/about
```

> [!NOTE]  
> When using `"v2"` strategy, make sure your logout URLs are registered in your Auth0 application's **Allowed Logout URLs** settings. The v2 endpoint supports wildcards in URLs.

### Federated logout

By default, the logout endpoint only logs the user out from Auth0's session. To also log the user out from their identity provider (such as Google, Facebook, or SAML IdP), you can use the `federated` parameter:

```html
<!-- Regular logout (Auth0 session only) -->
<a href="/auth/logout">Logout</a>

<!-- Federated logout (Auth0 + Identity Provider) -->
<a href="/auth/logout?federated">Logout from IdP</a>

<!-- Federated logout with custom returnTo -->
<a href="/auth/logout?federated&returnTo=https://example.com/goodbye">Logout from IdP</a>
```

The `federated` parameter works with all logout strategies (`auto`, `oidc`, and `v2`) and is passed through to the appropriate Auth0 logout endpoint:

- **OIDC logout**: `https://your-domain.auth0.com/oidc/logout?federated&...`
- **V2 logout**: `https://your-domain.auth0.com/v2/logout?federated&...`

### OIDC logout privacy configuration

The SDK provides control over whether to include the `id_token_hint` parameter in OIDC logout URLs through the `includeIdTokenHintInOIDCLogoutUrl` configuration option. This setting allows you to balance security and privacy based on your application's requirements.

#### Default behavior (recommended)

By default, the SDK includes `id_token_hint` in OIDC logout URLs for enhanced security:

```ts
export const auth0 = new Auth0Client({
  logoutStrategy: "auto", // or "oidc"
  includeIdTokenHintInOIDCLogoutUrl: true // default value
  // ... other config
});
```

#### Privacy-focused configuration

The default approach might include user information (PII) encoded in the ID token within logout URLs.
PII may appear in server logs, browser history, and referrer headers.
For applications where this is not acceptable, you can exclude `id_token_hint` from logout URLs:

```ts
export const auth0 = new Auth0Client({
  logoutStrategy: "auto", // or "oidc"
  includeIdTokenHintInOIDCLogoutUrl: false // exclude id_token_hint for privacy
  // ... other config
});
```

This will still send the `logout_hint` and `client_id` parameters.
This flag is only effective with the `oidc` or `auto` (uses `oidc` when possible) logout strategy.
This has no effect with v2 strategy (v2 doesn't use `id_token_hint`).

> [!WARNING]  
> When `includeIdTokenHintInOIDCLogoutUrl: false`, logout requests lose cryptographic verification. The [OpenID Connect specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#Security) warns that "logout requests without a valid `id_token_hint` value are a potential means of denial of service." Use this setting only when privacy requirements outweigh DoS protection concerns.

## Accessing the authenticated user

### In the browser

To access the currently authenticated user on the client, you can use the `useUser()` hook, like so:

```tsx
"use client";

import { useUser } from "@auth0/nextjs-auth0";

export default function Profile() {
  const { user, isLoading, error } = useUser();

  if (isLoading) return <div>Loading...</div>;

  return (
    <main>
      <h1>Profile</h1>
      <div>
        <pre>{JSON.stringify(user, null, 2)}</pre>
      </div>
    </main>
  );
}
```

#### Understanding `useUser()` Behavior

The `useUser()` hook uses SWR (Stale-While-Revalidate) under the hood, which provides smart caching and revalidation behavior. By default:

- **Event-driven revalidation**: Data automatically revalidates when you focus the browser tab, reconnect to the internet, or mount the component
- **No background polling**: The hook does **not** make continuous background requests unless explicitly configured
- **Cache-first approach**: Returns cached data immediately, then revalidates if needed
### On the server (App Router)

On the server, the `getSession()` helper can be used in Server Components, Server Routes, and Server Actions to get the session of the currently authenticated user and to protect resources, like so:

> [!NOTE]  
> The `getSession()` method returns a complete session object containing the user profile and all available tokens (access token, ID token, and refresh token when present). Use this method for applications that only need user identity information without calling external APIs, as it provides access to the user's profile data from the ID token without requiring additional API calls. This approach is suitable for session-only authentication patterns.
> For API access, use `getAccessToken()` to get an access token, this handles automatic token refresh.

```tsx
import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}!</h1>
    </main>
  );
}
```

### On the server (Pages Router)

On the server, the `getSession(req)` helper can be used in `getServerSideProps` and API routes to get the session of the currently authenticated user and to protect resources, like so:

```tsx
import type { GetServerSideProps, InferGetServerSidePropsType } from "next";

import { auth0 } from "@/lib/auth0";

export const getServerSideProps = (async (ctx) => {
  const session = await auth0.getSession(ctx.req);

  if (!session) return { props: { user: null } };

  return { props: { user: session.user ?? null } };
}) satisfies GetServerSideProps<{ user: any | null }>;

export default function Page({
  user
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  if (!user) {
    return (
      <main>
        <p>Not authenticated!</p>
      </main>
    );
  }

  return (
    <main>
      <p>Welcome, {user.name}!</p>
    </main>
  );
}
```

### Middleware

In middleware, the `getSession(req)` helper can be used to get the session of the currently authenticated user and to protect resources, like so:

```ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  // the headers from the auth middleware should always be returned
  return authRes;
}
```

> [!IMPORTANT]  
> The `request` object must be passed as a parameter to the `getSession(request)` method when called from a middleware to ensure that any updates to the session can be read within the same request.

## Protecting a Server-Side Rendered (SSR) Page

#### Page Router

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```jsx
// pages/profile.js
import { auth0 } from "@/lib/auth0";

export default function Profile({ user }) {
  return <div>Hello {user.name}</div>;
}

// You can optionally pass your own `getServerSideProps` function into
// `withPageAuthRequired` and the props will be merged with the `user` prop
export const getServerSideProps = auth0.withPageAuthRequired();
```

#### App Router

Requests to `/profile` without a valid session cookie will be redirected to the login page.

```jsx
// app/profile/page.js
import { auth0 } from "@/lib/auth0";

export default auth0.withPageAuthRequired(
  async function Profile() {
    const { user } = await auth0.getSession();
    return <div>Hello {user.name}</div>;
  },
  { returnTo: "/profile" }
);
// You need to provide a `returnTo` since Server Components aren't aware of the page's URL
```

## Protecting a Client-Side Rendered (CSR) Page

To protect a Client-Side Rendered (CSR) page, you can use the `withPageAuthRequired` higher-order function. Requests to `/profile` without a valid session cookie will be redirected to the login page.

```tsx
// app/profile/page.tsx
"use client";

import { withPageAuthRequired } from "@auth0/nextjs-auth0";

export default withPageAuthRequired(function Page({ user }) {
  return <div>Hello, {user.name}!</div>;
});
```

## Protect an API Route

### Page Router

Requests to `/api/protected` without a valid session cookie will fail with `401`.

```js
// pages/api/protected.js
import { auth0 } from "@/lib/auth0";

export default auth0.withApiAuthRequired(async function myApiRoute(req, res) {
  const { user } = await auth0.getSession(req);
  res.json({ protected: "My Secret", id: user.sub });
});
```

Then you can access your API from the frontend with a valid session cookie.

```jsx
// pages/products
import { withPageAuthRequired } from "@auth0/nextjs-auth0";
import useSWR from "swr";

const fetcher = async (uri) => {
  const response = await fetch(uri);
  return response.json();
};

export default withPageAuthRequired(function Products() {
  const { data, error } = useSWR("/api/protected", fetcher);
  if (error) return <div>oops... {error.message}</div>;
  if (data === undefined) return <div>Loading...</div>;
  return <div>{data.protected}</div>;
});
```

### App Router

Requests to `/api/protected` without a valid session cookie will fail with `401`.

```js
// app/api/protected/route.js
import { auth0 } from "@/lib/auth0";

export const GET = auth0.withApiAuthRequired(async function myApiRoute(req) {
  const res = new NextResponse();
  const { user } = await auth0.getSession(req);
  return NextResponse.json({ protected: "My Secret", id: user.sub }, res);
});
```

Then you can access your API from the frontend with a valid session cookie.

```jsx
// app/products/page.jsx
"use client";

import { withPageAuthRequired } from "@auth0/nextjs-auth0";
import useSWR from "swr";

const fetcher = async (uri) => {
  const response = await fetch(uri);
  return response.json();
};

export default withPageAuthRequired(function Products() {
  const { data, error } = useSWR("/api/protected", fetcher);
  if (error) return <div>oops... {error.message}</div>;
  if (data === undefined) return <div>Loading...</div>;
  return <div>{data.protected}</div>;
});
```

## Accessing the idToken

`idToken` can be accessed from the session in the following way:

```js
const session = await auth0.getSession();
const idToken = session.tokenSet.idToken;
```

## Updating the session

The `updateSession` method could be used to update the session of the currently authenticated user in the App Router, Pages Router, and middleware. If the user does not have a session, an error will be thrown.

> [!NOTE]
> Any updates to the session will be overwritten when the user re-authenticates and obtains a new session.

### On the server (App Router)

On the server, the `updateSession()` helper can be used in Server Routes and Server Actions to update the session of the currently authenticated user, like so:

```tsx
import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function GET() {
  const session = await auth0.getSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  await auth0.updateSession({
    ...session,
    updatedAt: Date.now()
  });

  return NextResponse.json(null, { status: 200 });
}
```

> [!NOTE]
> The `updateSession()` method is not usable in Server Components as it is not possible to write cookies.

### On the server (Pages Router)

On the server, the `updateSession(req, res, session)` helper can be used in `getServerSideProps` and API routes to update the session of the currently authenticated user, like so:

```tsx
import type { NextApiRequest, NextApiResponse } from "next";

import { auth0 } from "@/lib/auth0";

type ResponseData =
  | {}
  | {
      error: string;
    };

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ResponseData>
) {
  const session = await auth0.getSession(req);

  if (!session) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  await auth0.updateSession(req, res, {
    ...session,
    updatedAt: Date.now()
  });

  res.status(200).json({});
}
```

### Middleware

In middleware, the `updateSession(req, res, session)` helper can be used to update the session of the currently authenticated user, like so:

```ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  await auth0.updateSession(request, authRes, {
    ...session,
    user: {
      ...session.user,
      // add custom user data
      updatedAt: Date.now()
    }
  });

  // the headers from the auth middleware should always be returned
  return authRes;
}
```

> [!IMPORTANT]  
> The `request` and `response` objects must be passed as a parameters to the `updateSession(request, response, session)` method when called from a middleware to ensure that any updates to the session can be read within the same request.

If you are using the Pages Router and need to read updates to the session made in the middleware within the same request, you will need to ensure that any updates to the session are propagated on the request object, like so:

```ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  await auth0.updateSession(request, authRes, {
    ...session,
    user: {
      ...session.user,
      // add custom user data
      updatedAt: Date.now()
    }
  });

  // create a new response with the updated request headers
  const resWithCombinedHeaders = NextResponse.next({
    request: {
      headers: request.headers
    }
  });

  // set the response headers (set-cookie) from the auth response
  authRes.headers.forEach((value, key) => {
    resWithCombinedHeaders.headers.set(key, value);
  });

  // the headers from the auth middleware should always be returned
  return resWithCombinedHeaders;
}
```

## Getting an access token

The `getAccessToken()` helper can be used both in the browser and on the server to obtain the access token to call external APIs. If the access token has expired and a refresh token is available, it will automatically be refreshed and persisted.

> [!IMPORTANT]  
> **Refresh Token Rotation**: If your Auth0 application uses Refresh Token Rotation, configure an overlap period to prevent race conditions when multiple requests attempt to refresh tokens simultaneously. This can be configured in your Auth0 Dashboard under Applications > Advanced Settings > OAuth, or disable rotation entirely for server-side applications that don't require it.

### In the browser

To obtain an access token to call an external API on the client, you can use the `getAccessToken()` helper, like so:

```tsx
"use client";

import { getAccessToken } from "@auth0/nextjs-auth0";

export default function Component() {
  async function fetchData() {
    try {
      const token = await getAccessToken();
      // call external API with token...
    } catch (err) {
      // err will be an instance of AccessTokenError if an access token could not be obtained
    }
  }

  return (
    <main>
      <button onClick={fetchData}>Fetch Data</button>
    </main>
  );
}
```

### On the server (App Router)

On the server, the `getAccessToken()` helper can be used in Server Routes, Server Actions and Server Components to get an access token to call external APIs.

> [!IMPORTANT]  
> Server Components cannot set cookies. Calling `getAccessToken()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
>
> It is recommended to call `getAccessToken(req, res)` in the middleware if you need to use the refresh token in a Server Component as this will ensure the token is refreshed and correctly persisted.

For example:

```ts
import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function GET() {
  try {
    const token = await auth0.getAccessToken();
    // call external API with token...
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  return NextResponse.json({
    message: "Success!"
  });
}
```

### On the server (Pages Router)

On the server, the `getAccessToken(req, res)` helper can be used in `getServerSideProps` and API routes to get an access token to call external APIs, like so:

```ts
import type { NextApiRequest, NextApiResponse } from "next";

import { auth0 } from "@/lib/auth0";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<{ message: string }>
) {
  try {
    const token = await auth0.getAccessToken(req, res);
    // call external API with token...
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  res.status(200).json({ message: "Success!" });
}
```

### Middleware

In middleware, the `getAccessToken(req, res)` helper can be used to get an access token to call external APIs, like so:

```tsx
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  const accessToken = await auth0.getAccessToken(request, authRes);

  // the headers from the auth middleware should always be returned
  return authRes;
}
```

> [!IMPORTANT]  
> The `request` and `response` objects must be passed as a parameters to the `getAccessToken(request, response)` method when called from a middleware to ensure that the refreshed access token can be accessed within the same request.

If you are using the Pages Router and are calling the `getAccessToken` method in both the middleware and an API Route or `getServerSideProps`, it's recommended to propagate the headers from the middleware, as shown below. This will ensure that calling `getAccessToken` in the API Route or `getServerSideProps` will not result in the access token being refreshed again.

```ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  const accessToken = await auth0.getAccessToken(request, authRes);

  // create a new response with the updated request headers
  const resWithCombinedHeaders = NextResponse.next({
    request: {
      headers: request.headers
    }
  });

  // set the response headers (set-cookie) from the auth response
  authRes.headers.forEach((value, key) => {
    resWithCombinedHeaders.headers.set(key, value);
  });

  // the headers from the auth middleware should always be returned
  return resWithCombinedHeaders;
}
```

### Forcing Access Token Refresh

In some scenarios, you might need to explicitly force the refresh of an access token, even if it hasn't expired yet. This can be useful if, for example, the user's permissions or scopes have changed and you need to ensure the application has the latest token reflecting these changes.

The `getAccessToken` method provides an option to force this refresh.

**App Router (Server Components, Route Handlers, Server Actions):**

When calling `getAccessToken` without request and response objects, you can pass an options object as the first argument. Set the `refresh` property to `true` to force a token refresh.

```typescript
// app/api/my-api/route.ts
import { auth0 } from "@/lib/auth0";

export async function GET() {
  try {
    // Force a refresh of the access token
    const { token, expiresAt, scope } = await auth0.getAccessToken({ refresh: true });

    // Use the refreshed token
    // ...
  } catch (error) {
    console.error("Error getting access token:", error);
    return Response.json(
      { error: "Failed to get access token" },
      { status: 500 }
    );
  }
}
```

**Pages Router (getServerSideProps, API Routes):**

When calling `getAccessToken` with request and response objects (from `getServerSideProps` context or an API route), the options object is passed as the third argument.

```typescript
// pages/api/my-pages-api.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { getAccessToken, withApiAuthRequired } from "@auth0/nextjs-auth0";

export default withApiAuthRequired(async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    // Force a refresh of the access token
    const { token, expiresAt, scope } = await getAccessToken(req, res, {
      refresh: true
    });

    // Use the refreshed token
    // ...
  } catch (error: any) {
    console.error("Error getting access token:", error);
    res.status(error.status || 500).json({ error: error.message });
  }
});
```

By setting `{ refresh: true }`, you instruct the SDK to bypass the standard expiration check and request a new access token from the identity provider using the refresh token (if available and valid). The new token set (including the potentially updated access token, refresh token, and expiration time) will be saved back into the session automatically.
This will in turn, update the `access_token`, `id_token` and `expires_at` fields of `tokenset` in the session.


### Multi-Resource Refresh Tokens (MRRT)

Multi-Resource Refresh Tokens allow using a single refresh token to obtain access tokens for multiple audiences, simplifying token management in applications that interact with multiple backend services.

Read more about [Multi-Resource Refresh Tokens in the Auth0 documentation](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token).


> [!WARNING]
> When using Multi-Resource Refresh Token Configuration (MRRT), **Refresh Token Policies** on your Application need to be configured with the audiences you want to support. See the [Auth0 MRRT documentation](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token) for setup instructions.
>
> **Tokens requested for audiences outside your configured policies will be ignored by Auth0, which will return a token for the default audience instead!**

#### Basic Configuration

Configure a default audience in your Auth0 client initialization:

```typescript
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  authorizationParameters: {
    audience: "https://api.example.com", // Your default audience
    scope: "openid profile email offline_access read:products read:orders"
  }
});
```

##### Configuring Scopes Per Audience

When working with multiple APIs, you can define different default scopes for each audience by passing an object instead of a string. This is particularly useful when different APIs require different default scopes:

```typescript
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  authorizationParameters: {
    audience: "https://api.example.com", // Default audience
    scope: {
      "https://api.example.com": "openid profile email offline_access read:products read:orders",
      "https://analytics.example.com": "openid profile email offline_access read:analytics write:analytics",
      "https://admin.example.com": "openid profile email offline_access read:admin write:admin delete:admin"
    }
  }
});
```

**How it works:**

- Each key in the `scope` object is an `audience` identifier
- The corresponding value is the scope string for that audience
- When calling `getAccessToken({ audience: "..." })`, the SDK automatically uses the configured scopes for that audience. When scopes are also passed in the method call, they are be merged with the default scopes for that audience.

> [!NOTE]
> When using scope as an object, and no entry for the default audience is provided, the SDK defaults to `DEFAULT_SCOPE` (only for the default audience). This is the default audience used during authentication and determines which scope from the map is used for the initial login.

#### Usage Example

To retrieve access tokens for different audiences, use the `getAccessToken()` method with an `audience` (and optionally also the `scope`) parameter. Here's an example for an API Route:

```typescript
// app/api/data/route.ts
import { NextResponse } from "next/server";
import { auth0 } from "@/lib/auth0";

export async function GET() {
  try {
    // Get token for default audience
    const defaultToken = await auth0.getAccessToken();

    // Get token for different audience
    const dataToken = await auth0.getAccessToken({
      audience: "https://data-api.example.com"
    });

    // Get token with additional scopes
    const adminToken = await auth0.getAccessToken({
      audience: "https://admin.example.com",
      scope: "write:admin"
    });

    // Call external API with token
    const response = await fetch("https://data-api.example.com/data", {
      headers: { Authorization: `Bearer ${dataToken.token}` }
    });

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to fetch data" },
      { status: 500 }
    );
  }
}
```

> [!NOTE]
> The syntax for calling `getAccessToken()` may vary slightly depending on where it's being used. See the [Getting an access token](#getting-an-access-token) section for specific syntax examples for App Router (Server Components, API Routes, Server Actions), Pages Router (API Routes, `getServerSideProps`), Middleware, and client-side usage.

#### Token Management Best Practices

**Configure Broad Default Scopes**: Define comprehensive scopes in your `Auth0Client` constructor for common use cases. This minimizes the need to request additional scopes dynamically, reducing the amount of tokens that need to be stored.

```typescript
export const auth0 = new Auth0Client({
  authorizationParameters: {
    audience: "https://api.example.com",
    // Configure broad default scopes for most common operations
    scope: "openid profile email offline_access read:products read:orders read:users"
  }
});
```

**Minimize Dynamic Scope Requests**: Avoid passing `scope` when calling `getAccessToken()` unless absolutely necessary. Each `audience` + `scope` combination results in a token to store in the session, increasing session size.

```typescript
// Preferred: Use default scopes
const token = await auth0.getAccessToken({
  audience: "https://api.example.com"
});

// Avoid unless necessary: Dynamic scopes increase session size
const token = await auth0.getAccessToken({
  audience: "https://api.example.com",
  scope: "openid profile email read:products write:products admin:all"
});
```

**Consider Stateful Session Storage**: If your application requires strict least privilege with many dynamic scope requests, we recommend to use a [stateful session storage](#database-sessions) instead of cookie-based to avoid session size limitations.

### Mitigating Token Expiration Race Conditions in Latency-Sensitive Operations

For applications where an API call might be made very close to the token's expiration time, network latency can cause the token to expire before the API receives it. To prevent this race condition, you can implement a strategy to refresh the token proactively when it's within a certain buffer period of its expiration.

The general approach is as follows:

1. Before making a sensitive API call, get the session and check the `expiresAt` timestamp from the `tokenSet`.
2. Determine if the token is within your desired buffer period (e.g., 30-90 seconds) of expiring.
3. If it is, force a token refresh by calling `auth0.getAccessToken({ refresh: true })`.
4. Use the newly acquired access token for your API call.

This ensures that the token you send is guaranteed to be valid for at least the duration of the buffer, accounting for potential network delays.

> [!IMPORTANT]
> This strategy is **not** a solution for long-running operations that take longer than the token's total validity period (e.g., 10 minutes). In those cases, the token will still expire mid-operation. The correct approach for long-running tasks is to call `getAccessToken()` immediately before the operation that requires it, ensuring you have a fresh token. The buffer is only for mitigating latency-related failures in short-lived requests.

## DPoP (Demonstrating Proof-of-Possession)

DPoP is an OAuth 2.0 extension that enhances security by binding access tokens to a client's private key. This prevents token theft and replay attacks by requiring cryptographic proof that the client possessing the token also possesses the private key used to request it.

### What is DPoP?

DPoP (Demonstrating Proof-of-Possession) provides application-level proof-of-possession security for OAuth 2.0. Key benefits include:

- **Token Binding**: Access tokens are cryptographically bound to the client's key pair
- **Theft Protection**: Stolen tokens cannot be used without the corresponding private key  
- **Replay Attack Prevention**: Each request includes a unique proof-of-possession signature
- **Enhanced Security**: Complements OAuth 2.0 with additional cryptographic guarantees

### Basic DPoP Setup

Choose one of three setup methods based on your deployment strategy:

#### 1. Enable DPoP with Generated Keys

For dynamic key generation during application startup:

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { generateKeyPair } from "oauth4webapi";

// Generate ES256 key pair for DPoP - use this for development or dynamic environments
const dpopKeyPair = await generateKeyPair("ES256");

export const auth0 = new Auth0Client({
  useDPoP: true,
  dpopKeyPair
});
```

#### 2. Enable DPoP with Environment Variables

For production deployments with pre-generated keys:

```bash
# .env.local - Store your actual key values here
AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----"

AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQ...
-----END PRIVATE KEY-----"
```

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Auth0 client automatically loads keys from environment variables
export const auth0 = new Auth0Client({
  useDPoP: true
  // Keys loaded automatically from AUTH0_DPOP_* environment variables
});
```

#### 3. Generate DPoP Keys Using the SDK

For generating keys and exporting them to environment variables:

```typescript
import { generateDpopKeyPair } from "@auth0/nextjs-auth0/server";
import { exportSPKI, exportPKCS8 } from "jose";

// Generate new key pair and export for environment variables
const keyPair = await generateDpopKeyPair();
const publicKeyPem = await exportSPKI(keyPair.publicKey);
const privateKeyPem = await exportPKCS8(keyPair.privateKey);

// Copy these values to your .env.local file
console.log("AUTH0_DPOP_PUBLIC_KEY=" + publicKeyPem);
console.log("AUTH0_DPOP_PRIVATE_KEY=" + privateKeyPem);
```

### Making DPoP-Protected Requests

The recommended approach is to use the `createFetcher` method, which handles all DPoP complexity automatically.

#### Using the Fetcher (Recommended)

**App Router Example** - Server Components and Route Handlers:

```typescript
import { auth0 } from "@/lib/auth0";

// Route Handler: app/api/data/route.ts
export async function GET() {
  // Create fetcher with DPoP enabled and base URL for relative requests
  const fetcher = await auth0.createFetcher(undefined, {
    baseUrl: "https://api.example.com",
    useDPoP: true  // Enable DPoP for this fetcher instance
  });

  // Make authenticated request - DPoP proof generated automatically
  const response = await fetcher.fetchWithAuth("/protected-resource", {
    method: "GET",
    headers: {
      "Content-Type": "application/json"
    }
  });

  const data = await response.json();
  return Response.json(data);
}
```

**Pages Router Example** - API Routes and getServerSideProps:

```typescript
// API Route: pages/api/data.js
export default async function handler(req, res) {
  // Create fetcher with request context for session access
  const fetcher = await auth0.createFetcher(req, {
    baseUrl: "https://api.example.com",
    useDPoP: true
  });

  try {
    // fetchWithAuth handles access token retrieval and DPoP proof generation
    const response = await fetcher.fetchWithAuth("/protected-data");
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch data" });
  }
}
```

### DPoP Configuration Options

Fine-tune DPoP behavior for your environment and security requirements.

#### Clock Tolerance and Skew

Configure timing validation to handle clock differences between client and server:

```typescript
export const auth0 = new Auth0Client({
  useDPoP: true,
  dpopOptions: {
    // Clock tolerance: Allow up to 60 seconds difference between client/server clocks
    clockTolerance: 60,
    
    // Clock skew: Adjust if your server clock is consistently ahead/behind (rare)
    clockSkew: 0,
    
    // Retry configuration: Control behavior when DPoP nonce errors occur
    retry: {
      delay: 200,     // Wait 200ms before retry (prevents server overload)
      jitter: true    // Add randomness to prevent thundering herd effect
    }
  }
});
```

#### Environment Variable Configuration

Configure DPoP settings through environment variables for easier deployment:

```bash
# .env.local
# === Required: DPoP Keys ===
AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."

# === Optional: Timing Configuration ===
AUTH0_DPOP_CLOCK_SKEW=0           # Default: 0 (no adjustment)
AUTH0_DPOP_CLOCK_TOLERANCE=30     # Default: 30 seconds

# === Optional: Retry Configuration ===
AUTH0_RETRY_DELAY=100             # Default: 100ms delay before retry
AUTH0_RETRY_JITTER=true           # Default: true (add randomness)
```

### Error Handling

Handle DPoP-specific errors gracefully with proper error detection and response strategies.

#### Handling DPoP Errors

Implement comprehensive error handling for DPoP configuration and runtime issues:

```typescript
import { auth0 } from "@/lib/auth0";
import { DPoPError, DPoPErrorCode } from "@auth0/nextjs-auth0/server";

try {
  const fetcher = await auth0.createFetcher(req, {
    baseUrl: "https://api.example.com",
    useDPoP: true
  });

  const response = await fetcher.fetchWithAuth("/protected-resource");
  const data = await response.json();
  
  return Response.json(data);
} catch (error) {
  // Check for DPoP-specific errors first
  if (error instanceof DPoPError) {
    console.error(`DPoP Error [${error.code}]:`, error.message);
    
    // Handle specific DPoP error types
    switch (error.code) {
      case DPoPErrorCode.DPOP_KEY_EXPORT_FAILED:
        // Key configuration problem - check environment variables
        return Response.json(
          { error: "DPoP key configuration error" },
          { status: 500 }
        );
      case DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED:
        // Key thumbprint calculation failed - possible key corruption
        return Response.json(
          { error: "DPoP thumbprint calculation failed" },
          { status: 500 }
        );
      default:
        return Response.json(
          { error: "DPoP configuration error" },
          { status: 500 }
        );
    }
  }
  
  // Handle non-DPoP errors (network, API errors, etc.)
  return Response.json({ error: "Request failed" }, { status: 500 });
}
```

#### Automatic Nonce Error Retry

The SDK automatically handles DPoP nonce errors with intelligent retry logic:

```typescript
// The fetcher automatically retries DPoP nonce errors - no manual handling needed
const response = await fetcher.fetchWithAuth("/api/endpoint");

// Retry flow (handled internally):
// 1. First request → DPoP nonce error (401 with use_dpop_nonce header)
// 2. SDK extracts new nonce from error response
// 3. SDK waits configured delay (with optional jitter)
// 4. SDK retries request with updated nonce
// 5. Success or final failure
```

### Advanced Usage

#### Custom Access Token Factory

Override the default token retrieval with custom logic for specific use cases:

```typescript
const fetcher = await auth0.createFetcher(req, {
  baseUrl: "https://api.example.com",
  useDPoP: true,
  // Custom access token factory - useful for special scopes or audiences
  getAccessToken: async (options) => {
    // Add custom logic: token caching, audience-specific tokens, etc.
    const accessToken = await auth0.getAccessToken(req, {
      ...options,
      audience: "https://special-api.example.com",
      scope: "admin:read admin:write"
    });
    return accessToken.token;
  }
});
```

#### Custom Access Token Scopes with DPoP

Pass token options directly to individual requests:

```ts
// Specify audience and scope per request
const response = await fetcher.fetchWithAuth("/protected-resource", {
  scope: "read:admin write:admin",      // Request specific scopes
  audience: "https://api.example.com",  // Target specific API
  refresh: true                         // Force token refresh if needed
});
```

#### Conditional DPoP Usage

Enable DPoP selectively based on environment or security requirements:

```typescript
// Dynamic DPoP configuration based on environment or route sensitivity
const shouldUseDPoP = process.env.NODE_ENV === "production" || 
                      request.url.includes("/sensitive-api");

const fetcher = await auth0.createFetcher(req, {
  baseUrl: "https://api.example.com",
  useDPoP: shouldUseDPoP  // DPoP only for production or sensitive routes
});
```

#### Custom Fetch with DPoP

Add logging, metrics, or custom headers while preserving DPoP functionality:

```typescript
const fetcher = await auth0.createFetcher(req, {
  baseUrl: "https://api.example.com",
  useDPoP: true,
  // Custom fetch implementation with logging and metrics
  fetch: async (request) => {
    console.log(`DPoP request to: ${request.url}`);
    
    const startTime = Date.now();
    const response = await fetch(request);
    const duration = Date.now() - startTime;
    
    // Log response metrics
    console.log(`Response: ${response.status} (${duration}ms)`);
    
    // Could add custom headers, retry logic, etc.
    return response;
  }
});
```


### Token Audience Validation with Multiple APIs

When using DPoP with **multiple audiences** in the same application (e.g., via MRRT policies), ensure each access token is sent **only** to its intended API. Sending a token to the wrong API will result in audience validation failures.

#### How This Can Happen

When creating multiple fetcher instances for different APIs:

```javascript
// Fetcher for API 1
const fetcher1 = createFetcher({
  url: 'https://api1.example.com',
  accessTokenFactory: () => getAccessToken({
    audience: 'https://api1.example.com',
    // ...
  })
});

// Fetcher for API 2  
const fetcher2 = createFetcher({
  url: 'https://api2.example.com',
  accessTokenFactory: () => getAccessToken({
    audience: 'https://api2.example.com',
    // ...
  })
});
```

**Common mistake**: Accidentally using `fetcher1` to call endpoints that should use `fetcher2`, or vice versa. The API will reject the request with an audience mismatch error like:

```
OAUTH_JWT_CLAIM_COMPARISON_FAILED: unexpected JWT "aud" (audience) claim value
```

#### Mitigation Strategies

**1. Scope fetcher instances appropriately**
- Create one fetcher per API/audience combination
- Use clear, descriptive variable names that indicate which API each fetcher targets
- Consider namespacing or module organization to prevent confusion

**2. Configure MRRT policies correctly**
- Ensure your MRRT policies include all audiences your application needs to access
- Set `skip_consent_for_verifiable_first_party_clients: true` on all APIs in MRRT policies
- Only include **custom scopes** in MRRT policies (OIDC scopes like `openid`, `profile`, `offline_access` are automatically included)

**3. Validate in development**
- Log the `aud` claim from decoded tokens during development to verify correct routing
- Implement error handling that clearly identifies audience mismatches
- Test each fetcher instance against its intended API endpoint before production deployment

**4. API server validation**
- Ensure your API servers validate the `aud` claim matches their expected audience identifier
- Use the same audience string in both Auth0 API configuration and server-side validation

#### Example: Proper Token Routing

```javascript
// ✅ Correct: Each fetcher calls its own API
await fetcher1.fetchWithAuth('/users'); // Uses token with aud: "https://api1.example.com"
await fetcher2.fetchWithAuth('/orders'); // Uses token with aud: "https://api2.example.com"

// ❌ Incorrect: Wrong fetcher for the API
await fetcher1.fetchWithAuth('https://api2.example.com/orders'); // Will fail with aud mismatch
```

**Remember**: JWT audience validation is a critical security feature that prevents token misuse across different resource servers. These errors indicate your security controls are working correctly—the solution is to ensure proper token-to-API routing in your application code.

### Security Best Practices

Follow these guidelines for secure DPoP implementation:

- **Key Management**: Use hardware security modules (HSMs) for key storage in production
- **Key Rotation**: Implement regular key rotation policies for long-lived applications  
- **Monitoring**: Monitor DPoP error rates to detect potential attacks or configuration issues
- **Clock Tolerance**: Keep clock tolerance as low as possible (≤ 30 seconds recommended)
- **Environment Isolation**: Use unique key pairs per environment (dev, staging, production)
- **Key Security**: Never commit DPoP keys to version control or logs

### Troubleshooting

Diagnose and resolve common DPoP configuration and runtime issues.

#### Common Issues

**DPoP keys not found:**
```
WARNING: useDPoP is set to true but dpopKeyPair is not provided.
```
**Solution**: Ensure `AUTH0_DPOP_PUBLIC_KEY` and `AUTH0_DPOP_PRIVATE_KEY` are set correctly in your environment, or provide the `dpopKeyPair` option directly in the Auth0Client constructor.

**Key pair validation failed:**
```
WARNING: Private and public keys do not form a valid key pair
```
**Solution**: Verify that your keys are correctly paired, in PEM format, and use the P-256 elliptic curve. Regenerate keys if necessary using the SDK's `generateDpopKeyPair()` function.

**Clock tolerance warnings:**
```
WARNING: clockTolerance of 300s exceeds recommended maximum of 30s
```
**Solution**: Synchronize server clocks using NTP instead of increasing tolerance. High tolerance values weaken DPoP security.

**DPoP nonce errors:**
If you see frequent nonce errors, check:
- **Server clock synchronization**: Ensure clocks are accurate and synced
- **Network stability**: Verify stable connection between client and authorization server  
- **Rate limiting**: Check if authorization server is rate limiting requests

#### Debug Logging

Enable detailed logging to diagnose DPoP request issues:

```typescript
// Custom fetch with comprehensive DPoP debugging
const fetcher = await auth0.createFetcher(req, {
  baseUrl: "https://api.example.com",
  useDPoP: true,
  fetch: async (request) => {
    // Log outgoing request details
    console.log("DPoP Request Headers:", 
      Object.fromEntries(request.headers.entries())
    );
    
    const response = await fetch(request);
    
    // Log response details, especially for failures
    if (!response.ok) {
      console.error("DPoP Request Failed:", {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries())
      });
    }
    
    return response;
  }
});
```


## `<Auth0Provider />`

### Passing an initial user from the server

You can wrap your components in an `<Auth0Provider />` and pass an initial user object to make it available to your components using the `useUser()` hook. For example:

```tsx
import { Auth0Provider } from "@auth0/nextjs-auth0";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export default async function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  const session = await auth0.getSession();

  return (
    <html lang="en">
      <body>
        <Auth0Provider user={session?.user}>{children}</Auth0Provider>
      </body>
    </html>
  );
}
```

The loaded user will then be used as a fallback in `useUser()` hook.

## Hooks

The SDK exposes hooks to enable you to provide custom logic that would be run at certain lifecycle events.

### `beforeSessionSaved`

The `beforeSessionSaved` hook is run right before the session is persisted. It provides a mechanism to modify the session claims before persisting them.

The hook recieves a `SessionData` object and an ID token. The function must return a Promise that resolves to a `SessionData` object: `(session: SessionData) => Promise<SessionData>`. For example:

```ts
import {
  Auth0Client,
  filterDefaultIdTokenClaims
} from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  async beforeSessionSaved(session, idToken) {
    return {
      ...session,
      user: {
        ...filterDefaultIdTokenClaims(session.user),
        foo: session.user.foo // keep the foo claim
      }
    };
  }
});
```

The `session.user` object passed to the `beforeSessionSaved` hook will contain every claim in the ID Token, including custom claims. You can use the `filterDefaultIdTokenClaims` utility to filter out the standard claims and only keep the custom claims you want to persist.

> [!INFO]  
> Incase you want to understand which claims are being considered the default Id Token Claims, you can refer to `DEFAULT_ID_TOKEN_CLAIMS`, which can be imported from the SDK from `@auth0/nextjs-auth0/server`:
>
> ```ts
> import { DEFAULT_ID_TOKEN_CLAIMS } from "@auth0/nextjs-auth0/server";
> ```

Alternatively, you can use the entire `session.user` object if you would like to include every claim in the ID Token by just returning the `session` like so:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  async beforeSessionSaved(session, idToken) {
    return session;
  }
});
```

Do realize that this has an impact on the size of the cookie being issued, so it's best to limit the claims to only those that are necessary for your application.

### `onCallback`

The `onCallback` hook is run once the user has been redirected back from Auth0 to your application with either an error or the authorization code which will be verified and exchanged.

The `onCallback` hook receives 3 parameters:

1. `error`: the error returned from Auth0 or when attempting to complete the transaction. This will be `null` if the transaction was completed successfully.
2. `context`: provides context on the transaction that initiated the transaction.
3. `session`: the `SessionData` that will be persisted once the transaction completes successfully. This will be `null` if there was an error.

The hook must return a Promise that resolves to a `NextResponse`.

For example, a custom `onCallback` hook may be specified like so:

```ts
export const auth0 = new Auth0Client({
  async onCallback(error, context, session) {
    // redirect the user to a custom error page
    if (error) {
      return NextResponse.redirect(
        new URL(`/error?error=${error.message}`, process.env.APP_BASE_URL)
      );
    }

    // complete the redirect to the provided returnTo URL
    return NextResponse.redirect(
      new URL(context.returnTo || "/", process.env.APP_BASE_URL)
    );
  }
});
```

## Session configuration

The session configuration can be managed by specifying a `session` object when configuring the Auth0 client, like so:

```ts
export const auth0 = new Auth0Client({
  session: {
    rolling: true,
    absoluteDuration: 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration: 60 * 60 * 24 * 7 // 7 days in seconds
  }
});
```

| Option             | Type      | Description                                                                                                                                                                                                                                   |
| ------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| rolling            | `boolean` | When enabled, the session will continue to be extended as long as it is used within the inactivity duration. Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended. Default: `true`. |
| absoluteDuration   | `number`  | The absolute duration after which the session will expire. The value must be specified in seconds. Default: `3 days`.                                                                                                                         |
| inactivityDuration | `number`  | The duration of inactivity after which the session will expire. The value must be specified in seconds. Default: `1 day`.                                                                                                                     |

### Understanding Rolling Sessions

Rolling sessions provide a seamless user experience by automatically extending session lifetime as users actively use your application. Here's how they work:

**How rolling sessions work:**
- Each request to your application extends the session by the `inactivityDuration`
- Sessions are only extended if used within the inactivity window
- Once the `absoluteDuration` is reached, sessions expire regardless of activity
- Session extension happens transparently without user intervention

**Middleware requirement:**
Rolling sessions **require** the authentication middleware to run on all requests. This is why the recommended middleware matcher is broad:

```ts
// ✅ CORRECT: Broad matcher enables rolling sessions
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)]
};

// ❌ INCORRECT: Narrow matcher breaks rolling sessions  
export const config = {
  matcher: ["/dashboard/:path*", "/profile/:path*"]
};
```

**Why broad middleware is necessary:**
- **Session extension**: Each page request extends the session lifetime
- **Consistent auth state**: Ensures authentication status is up-to-date across all pages
- **Security headers**: Applies no-cache headers to prevent caching of authenticated content

> [!WARNING]
> Disabling rolling sessions changes the user experience significantly. Users will be logged out after the absolute duration regardless of their activity level, requiring manual re-authentication.

## Cookie Configuration

You can configure the session cookie attributes either through environment variables or directly in the SDK initialization.

**1. Using Environment Variables:**

Set the desired environment variables in your `.env.local` file or your deployment environment:

```
# .env.local
# ... other variables ...

# Cookie Options
AUTH0_COOKIE_DOMAIN='.example.com' # Set cookie for subdomains
AUTH0_COOKIE_PATH='/app'          # Limit cookie to /app path
AUTH0_COOKIE_TRANSIENT=true       # Make cookie transient (session-only)
AUTH0_COOKIE_SECURE=true          # Recommended for production
AUTH0_COOKIE_SAME_SITE='Lax'
```

The SDK will automatically pick up these values. Note that `httpOnly` is always set to `true` for security reasons and cannot be configured.

**2. Using `Auth0ClientOptions`:**

Configure the options directly when initializing the client:

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  session: {
    cookie: {
      domain: ".example.com",
      path: "/app",
      transient: true,
      // httpOnly is always true and cannot be configured
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax"
      // name: 'appSession', // Optional: custom cookie name, defaults to '__session'
    }
    // ... other session options like absoluteDuration ...
  }
  // ... other client options ...
});
```

**Session Cookie Options:**

- `domain` (String): Specifies the `Domain` attribute.
- `path` (String): Specifies the `Path` attribute. Defaults to `/`.
- `transient` (Boolean): If `true`, the `maxAge` attribute is omitted, making it a session cookie. Defaults to `false`.
- `secure` (Boolean): Specifies the `Secure` attribute. Defaults to `false` (or `true` if `AUTH0_COOKIE_SECURE=true` is set).
- `sameSite` ('Lax' | 'Strict' | 'None'): Specifies the `SameSite` attribute. Defaults to `Lax` (or the value of `AUTH0_COOKIE_SAME_SITE`).
- `name` (String): The name of the session cookie. Defaults to `__session`.

> [!INFO]
> Options provided directly in `Auth0ClientOptions` take precedence over environment variables. The `httpOnly` attribute is always `true` regardless of configuration.

> [!INFO]
> The `httpOnly` attribute for the session cookie is always set to `true` for security reasons and cannot be configured via options or environment variables.

## Transaction Cookie Configuration

### Customizing Transaction Cookie Expiration

You can configure transaction cookies expiration by providing a `maxAge` property for `transactionCookie`.

```ts
export const auth0 = new Auth0Client({
  transactionCookie: {
    maxAge: 1800, // 30 minutes (in seconds)
    // ... other options
  },
}
```

Transaction cookies are used to maintain state during authentication flows. The SDK provides several configuration options to manage transaction cookie behavior and prevent cookie accumulation issues.

### Transaction Management Modes

**Parallel Transactions (Default)**

```ts
const authClient = new Auth0Client({
  enableParallelTransactions: true // Default: allows multiple concurrent logins
  // ... other options
});
```

**Single Transaction Mode**

```ts
const authClient = new Auth0Client({
  enableParallelTransactions: false // Only one active transaction at a time
  // ... other options
});
```

**Use Parallel Transactions (Default) When:**

- Users might open multiple tabs and attempt to log in simultaneously
- You want maximum compatibility with typical user behavior
- Your application supports multiple concurrent authentication flows

**Use Single Transaction Mode When:**

- You want to prevent cookie accumulation issues in applications with frequent login attempts
- You prefer simpler transaction management
- Users typically don't need multiple concurrent login flows
- You're experiencing cookie header size limits due to abandoned transaction cookies edge cases

### Transaction Cookie Options

| Option                 | Type                          | Description                                                                                                                                                    |
| ---------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cookieOptions.maxAge   | `number`                      | The expiration time for transaction cookies in seconds. Defaults to `3600` (1 hour). After this time, abandoned transaction cookies will expire automatically. |
| cookieOptions.prefix   | `string`                      | The prefix for transaction cookie names. Defaults to `__txn_`. In parallel mode, cookies are named `__txn_{state}`. In single mode, just `__txn_`.             |
| cookieOptions.sameSite | `"strict" \| "lax" \| "none"` | Controls when the cookie is sent with cross-site requests. Defaults to `"lax"`.                                                                                |
| cookieOptions.secure   | `boolean`                     | When `true`, the cookie will only be sent over HTTPS connections. Automatically determined based on your application's base URL protocol if not specified.     |
| cookieOptions.path     | `string`                      | Specifies the URL path for which the cookie is valid. Defaults to `"/"`.                                                                                       |

## Database sessions

By default, the user's sessions are stored in encrypted cookies. You may choose to persist the sessions in your data store of choice.

To do this, you can provide a `SessionStore` implementation as an option when configuring the Auth0 client, like so:

```ts
export const auth0 = new Auth0Client({
  sessionStore: {
    async get(id) {
      // query and return a session by its ID
    },
    async set(id, sessionData) {
      // upsert the session given its ID and sessionData
    },
    async delete(id) {
      // delete the session using its ID
    },
    async deleteByLogoutToken({ sid, sub }: { sid?: string; sub?: string }) {
      // optional method to be implemented when using Back-Channel Logout
    }
  }
});
```

## Using Client-Initiated Backchannel Authentication

Using Client-Initiated Backchannel Authentication can be done by calling `getTokenByBackchannelAuth()`:

```ts
import { auth0 } from "@/lib/auth0";

const tokenResponse = await auth0.getTokenByBackchannelAuth({
  bindingMessage: "",
  loginHint: {
    sub: "auth0|123456789"
  }
});
```

- `bindingMessage`: A human-readable message to be displayed at the consumption device and authentication device. This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
- `loginHint.sub`: The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.

> [!IMPORTANT]  
> Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
> Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

## Connected Accounts

The SDK can be configured to mount an endpoint to facilitate the connected accounts flow. To mount this route, set the `enableConnectAccountEndpoint` option to `true` when instantiating the Auth0 client, like so:

```ts
// ./lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  enableConnectAccountEndpoint: true
});
```

By default, the route will be mounted at `/auth/connect`. You can customize this path by specifying a `routes.connectAccount` option, like so:

```ts
// ./lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  enableConnectAccountEndpoint: true,
  routes: {
    connectAccount: "/auth/connect"
  }
});
```

The connect endpoint (`/auth/connect` or your custom path) accepts the following query parameters:

- `connection`: (required) the name of the connection to use for linking the account
- `returnTo`: (optional) the URL to redirect the user to after they have completed the connection flow.
- Any additional parameters will be passed as the `authorizationParams` in the call to `/me/v1/connected-accounts/connect`.

### `onCallback` hook

When a user is redirected back to your application after completing the connected accounts flow, the `onCallback` hook will be called. You can use this hook to run custom logic after the user has connected their account, like so:

```ts
import { NextResponse } from "next/server";
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  async onCallback(err, ctx, session) {
    // `ctx` will contain the following properties when handling a connected account callback:
    // - `connectedAccount`: the connected account object (`CompleteConnectAccountResponse`) if the connection was successful
    // - `responseType`: will be set to `connect_code` when handling a connected accounts callback (`RESPONSE_TYPES.ConnectCode`)
    // - `returnTo`: the returnTo URL specified when calling the connect endpoint (if any)

    return NextResponse.redirect(
      new URL(ctx.returnTo ?? "/", process.env.APP_BASE_URL)
    );
  },
  enableConnectAccountEndpoint: true
});
```

### `connectAccount` method

In case you'd like to have more control over the connected accounts flow, a `connectAccount` method is also available on the Auth0 client instance. For example, you could mount a custom route to start the connected accounts flow, like so:

```ts
import { auth0 } from "@/lib/auth0";

export async function GET() {
  const res = await auth0.connectAccount({
    connection: "my-connection",
    authorizationParams: {
      scope: "openid profile offline_access read:something",
      prompt: "consent",
      audience: "https://myapi.com"
    },
    returnTo: "/connected"
  });

  return res;
}
```

## Back-Channel Logout

The SDK can be configured to listen to [Back-Channel Logout](https://auth0.com/docs/authenticate/login/logout/back-channel-logout) events. By default, a route will be mounted `/auth/backchannel-logout` which will verify the logout token and call the `deleteByLogoutToken` method of your session store implementation to allow you to remove the session.

To use Back-Channel Logout, you will need to provide a session store implementation as shown in the [Database sessions](#database-sessions) section above with the `deleteByLogoutToken` implemented.

A `LogoutToken` object will be passed as the parameter to `deleteByLogoutToken` which will contain either a `sid` claim, a `sub` claim, or both.

## Combining middleware

By default, the middleware does not protect any pages. It is used to mount the authentication routes and provide the necessary functionality for rolling sessions.

You can combine multiple middleware, like so:

> [!WARNING] > **Handling `x-middleware-next` Header**
> The `auth0.middleware` response (`authResponse`) might contain an `x-middleware-next` header. This header signals to Next.js that the request should be forwarded to the backend application, regardless of the status code of the response you construct.
>
> When combining middleware, **do not** copy the `x-middleware-next` header from `authResponse` to your final response if your custom middleware intends to block the request (e.g., by returning a `NextResponse.json` with a 401 status, or a `NextResponse.redirect`). Copying this header in such cases will cause Next.js to still execute the backend route handler despite your middleware attempting to block access. Only copy headers that are necessary, like `set-cookie`.

```ts
export async function middleware(request: NextRequest) {
  const authResponse = await auth0.middleware(request);

  // if path starts with /auth, let the auth middleware handle it
  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authResponse;
  }

  // call any other middleware here
  const someOtherResponse = await someOtherMiddleware(request);
  const shouldProceed = someOtherResponse.headers.get("x-middleware-next");

  // add any headers from the auth middleware to the response
  for (const [key, value] of authResponse.headers) {
    // Only copy 'x-middleware-next' if the custom middleware response intends to proceed.
    if (key.toLowerCase() === "x-middleware-next" && !shouldProceed) {
      continue; // Skip copying this header if we are blocking/redirecting
    }
    someOtherResponse.headers.set(key, value);
  }

  return someOtherResponse;
}
```

For a complete example using `next-intl` middleware, please see the `examples/` directory of this repository.

## ID Token claims and the user object

By default, the following properties claims from the ID token are added to the `user` object in the session automatically:

- `sub`
- `name`
- `nickname`
- `given_name`
- `family_name`
- `picture`
- `email`
- `email_verified`
- `org_id`

If you'd like to customize the `user` object to include additional custom claims from the ID token, you can use the `beforeSessionSaved` hook (see [beforeSessionSaved hook](#beforesessionsaved))

> [!NOTE]  
> It's best practice to limit what claims are stored on the `user` object in the session to avoid bloating the session cookie size and going over browser limits.

## Routes

The SDK mounts 6 routes:

1. `/auth/login`: the login route that the user will be redirected to to start a initiate an authentication transaction
2. `/auth/logout`: the logout route that must be added to your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be added to your Auth0 application's Allowed Callback URLs
4. `/auth/profile`: the route to check the user's session and return their attributes
5. `/auth/access-token`: the route to check the user's session and return an access token (which will be automatically refreshed if a refresh token is available)
6. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

### Custom routes

The default paths can be set using the `routes` configuration option. For example, when instantiating the client:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  routes: {
    login: "/login",
    logout: "/logout",
    callback: "/callback",
    backChannelLogout: "/backchannel-logout"
  }
});
```

> [!NOTE]  
> If you customize the login url you will need to set the environment variable `NEXT_PUBLIC_LOGIN_ROUTE` to this custom value for `withPageAuthRequired` to work correctly.

To configure the profile and access token routes, you must use the `NEXT_PUBLIC_PROFILE_ROUTE` and `NEXT_PUBLIC_ACCESS_TOKEN_ROUTE`, respectively. For example:

```
# .env.local
# required environment variables...

NEXT_PUBLIC_PROFILE_ROUTE=/api/me
NEXT_PUBLIC_ACCESS_TOKEN_ROUTE=/api/auth/token
```

> [!IMPORTANT]  
> Updating the route paths will also require updating the **Allowed Callback URLs** and **Allowed Logout URLs** configured in the [Auth0 Dashboard](https://manage.auth0.com) for your client.

## Testing helpers

### `generateSessionCookie`

The `generateSessionCookie` helper can be used to generate a session cookie value for use during tests:

```ts
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

const sessionCookieValue = await generateSessionCookie(
  {
    user: {
      sub: "user_123"
    },
    tokenSet: {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: 123456789
    }
  },
  {
    secret: process.env.AUTH0_SECRET!
  }
);
```

## Programmatically starting interactive login

Additionally to the ability to initialize the interactive login process by redirecting the user to the built-in `auth/login` endpoint,
the `startInteractiveLogin` method can also be called programmatically.

```typescript
import { NextRequest } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export const GET = async (req: NextRequest) => {
  return auth0.startInteractiveLogin();
};
```

### Passing authorization parameters

There are 2 ways to customize the authorization parameters that will be passed to the `/authorize` endpoint when calling `startInteractiveLogin` programmatically. The first option is through static configuration when instantiating the client, like so:

```ts
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email",
    audience: "urn:custom:api"
  }
});
```

The second option is by configuring `authorizationParams` when calling `startInteractiveLogin`:

```ts
import { NextRequest } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export const GET = async (req: NextRequest) => {
  // Call startInteractiveLogin with optional parameters
  return auth0.startInteractiveLogin({
    authorizationParameters: {
      scope: "openid profile email",
      audience: "urn:custom:api"
    }
  });
};
```

## The `returnTo` parameter

### Redirecting the user after authentication

When calling `startInteractiveLogin`, the `returnTo` parameter can be configured to specify where you would like to redirect the user to after they have completed their authentication and have returned to your application.

```ts
import { NextRequest } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export const GET = async (req: NextRequest) => {
  return auth0.startInteractiveLogin({
    returnTo: "/dashboard"
  });
};
```

> [!NOTE]  
> The URLs specified as `returnTo` parameters must be registered in your client's **Allowed Callback URLs**.

## Getting access tokens for connections

You can retrieve an access token for a connection using the `getAccessTokenForConnection()` method, which accepts an object with the following properties:

- `connection`: The federated connection for which an access token should be retrieved.
- `login_hint`: The optional login_hint parameter to pass to the `/authorize` endpoint.

### On the server (App Router)

On the server, the `getAccessTokenForConnection()` helper can be used in Server Routes, Server Actions and Server Components to get an access token for a connection.

> [!IMPORTANT]  
> Server Components cannot set cookies. Calling `getAccessTokenForConnection()` in a Server Component will cause the access token to be refreshed, if it is expired, and the updated token set will not to be persisted.
>
> It is recommended to call `getAccessTokenForConnection(req, res)` in the middleware if you need to refresh the token in a Server Component as this will ensure the token is refreshed and correctly persisted.

For example:

```ts
import { NextResponse } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function GET() {
  try {
    const token = await auth0.getAccessTokenForConnection({
      connection: "google-oauth2"
    });
    // call external API with token...
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  return NextResponse.json({
    message: "Success!"
  });
}
```

Upon further calls for the same provider, the cached value will be used until it expires.

### On the server (Pages Router)

On the server, the `getAccessTokenForConnection({}, req, res)` helper can be used in `getServerSideProps` and API routes to get an access token for a connection, like so:

```ts
import type { NextApiRequest, NextApiResponse } from "next";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<{ message: string }>
) {
  try {
    const token = await auth0.getAccessTokenForConnection(
      { connection: "google-oauth2" },
      req,
      res
    );
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  res.status(200).json({ message: "Success!" });
}
```

### Middleware

In middleware, the `getAccessTokenForConnection({}, req, res)` helper can be used to get an access token for a connection, like so:

```tsx
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  const accessToken = await auth0.getAccessTokenForConnection(
    { connection: "google-oauth2" },
    request,
    authRes
  );

  // the headers from the auth middleware should always be returned
  return authRes;
}
```

> [!IMPORTANT]  
> The `request` and `response` objects must be passed as a parameters to the `getAccessTokenForConnection({}, request, response)` method when called from a middleware to ensure that the refreshed access token can be accessed within the same request.

If you are using the Pages Router and are calling the `getAccessTokenForConnection` method in both the middleware and an API Route or `getServerSideProps`, it's recommended to propagate the headers from the middleware, as shown below. This will ensure that calling `getAccessTokenForConnection` in the API Route or `getServerSideProps` will not result in the access token being refreshed again.

```ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes;
  }

  const session = await auth0.getSession(request);

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(
      new URL("/auth/login", request.nextUrl.origin)
    );
  }

  const accessToken = await auth0.getAccessTokenForConnection(
    { connection: "google-oauth2" },
    request,
    authRes
  );

  // create a new response with the updated request headers
  const resWithCombinedHeaders = NextResponse.next({
    request: {
      headers: request.headers
    }
  });

  // set the response headers (set-cookie) from the auth response
  authRes.headers.forEach((value, key) => {
    resWithCombinedHeaders.headers.set(key, value);
  });

  // the headers from the auth middleware should always be returned
  return resWithCombinedHeaders;
}
```

## Customizing Auth Handlers

Authentication routes (`/auth/login`, `/auth/logout`, `/auth/callback`) are handled automatically by the middleware. You can intercept these routes in your middleware to run custom logic before the auth handlers execute.

This approach allows you to:

- Run custom code before authentication actions (logging, analytics, validation)
- Modify the response (set cookies, headers, etc.)
- Implement custom redirects or early returns when needed
- Add business logic around authentication flows
- Maintain compatibility with existing tracking and analytics systems

The middleware-based approach provides the same level of control as v3's custom handlers while working seamlessly with v4's automatic route handling.

### Run custom code before Auth Handlers

Following example shows how to run custom logic before the response of `logout` handler is returned:

```ts
export async function middleware(request) {
  // prepare NextResponse object from auth0 middleware
  const authRes = await auth0.middleware(request);

  // The following interceptUrls can be used:
  //    "/auth/login" : intercept login auth handler
  //    "/auth/logout" : intercept logout auth handler
  //    "/auth/callback" : intercept callback auth handler
  //    "/your/login/returnTo/url" : intercept redirect after login, this is the login returnTo url
  //    "/your/logout/returnTo/url" : intercept redirect after logout, this is the logout returnTo url

  const interceptUrl = "/auth/logout";

  // intercept auth handler
  if (request.nextUrl.pathname === interceptUrl) {
    // do custom stuff
    console.log("Pre-logout code");

    // Example: Set a cookie
    authRes.cookies.set("myCustomCookie", "cookieValue", { path: "/" });
    // Example: Set another cookie with options
    authRes.cookies.set({
      name: "anotherCookie",
      value: "anotherValue",
      httpOnly: true,
      path: "/"
    });

    // Example: Delete a cookie
    // authRes.cookies.delete('cookieNameToDelete');

    // you can also do an early return here with your own NextResponse object
    // return NextResponse.redirect(new URL('/custom-logout-page'));
  }

  // return the original auth0-handled NextResponse object
  return authRes;
}
```

### Run code after callback

Please refer to [onCallback](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oncallback) for details on how to run code after callback.
