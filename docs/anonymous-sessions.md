# Anonymous Sessions

Anonymous sessions enable your Next.js application to provide a pre-login identity backed by an access token, without requiring user credentials. This allows you to offer API calls, personalization, and metadata storage to visitors before they log in.

An anonymous session is represented by an `anon@{uuid}` identity and includes:

- **Access Token**: A bearer token issued to the anonymous identity. Configure `anonymousSession.audience` to target a specific API. When you leave it unset, the authorization server issues the token for your tenant's default audience, which is generally not accepted by your own APIs.
- **Session Token**: An opaque handle, held server-side only, that drives token renewal
- **Expiration**: Unix timestamp indicating when the access token expires
- **Metadata**: Optional user-defined key-value data (up to 1 KB)

Anonymous sessions are completely independent from authenticated user sessions. They do not interact with login/logout flows unless your application explicitly coordinates them.

## Table of Contents

- [Enabling Anonymous Sessions](#enabling-anonymous-sessions)
  - [Configuration Options](#configuration-options)
  - [Overriding Routes](#overriding-routes)
- [Server-Side Usage](#server-side-usage)
  - [Getting the Current Session](#getting-the-current-session)
  - [Creating a New Session](#creating-a-new-session)
- [Client-Side Usage](#client-side-usage)
  - [The `useAnonymousSession` Hook](#the-useanonymoussession-hook)
  - [Provider Seeding](#provider-seeding)
- [Working with Metadata](#working-with-metadata)
- [Logging Out](#logging-out)
- [Error Handling](#error-handling)
  - [Error Codes and HTTP Status](#error-codes-and-http-status)
- [Security and Limitations](#security-and-limitations)
  - [The session token travels in the authorization request URL](#the-session-token-travels-in-the-authorization-request-url)
  - [Other security properties](#other-security-properties)
  - [Known Limitations](#known-limitations)
- [Type Reference](#type-reference)
- [Examples](#examples)

## Enabling Anonymous Sessions

To enable anonymous sessions, pass the `anonymousSession` configuration to your Auth0Client:

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  anonymousSession: {
    enabled: true,
    audience: "https://api.example.com", // optional; defaults to the tenant default audience
    scope: "read:catalog", // optional; defaults to no requested scope
    cookie: {
      name: "auth0_anon", // optional; defaults to "auth0_anon"
      sameSite: "lax", // optional; defaults to "lax"
      secure: true, // optional; defaults to true
      maxAge: 2592000 // optional; cookie lifetime in seconds, defaults to 2592000 (30 days)
    }
  }
});
```

### Configuration Options

| Option            | Type                          | Default        | Description                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------- | ----------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`         | `boolean`                     | `false`        | Master switch. When `true`, the feature routes are mounted and the server methods are active. When `false`, the routes return 404, `getAnonymousSession()` returns `null`, and `createAnonymousSession()` throws `unauthorized_client`.                                                                                                                                                   |
| `audience`        | `string`                      | none           | API identifier the anonymous access token is issued for. Sent on session creation and on every renewal so the audience survives re-minting. When unset, the authorization server issues the token for your tenant's default audience.                                                                                                                                                     |
| `scope`           | `string`                      | none           | Space-separated scopes requested for the anonymous access token. Sent on session creation and on every renewal. When unset, the SDK requests no `scope` and the authorization server applies your tenant default.                                                                                                                                                                         |
| `cookie.name`     | `string`                      | `"auth0_anon"` | Name of the encrypted cookie storing the anonymous session.                                                                                                                                                                                                                                                                                                                               |
| `cookie.sameSite` | `"lax" \| "strict" \| "none"` | `"lax"`        | SameSite attribute for the cookie. Set to `"none"` only if absolutely necessary, and always with `secure: true`.                                                                                                                                                                                                                                                                          |
| `cookie.secure`   | `boolean`                     | `true`         | Secure flag for the cookie.                                                                                                                                                                                                                                                                                                                                                               |
| `cookie.maxAge`   | `number`                      | `2592000`      | Cookie lifetime in seconds. Defaults to 2592000 (30 days). The anonymous access token is renewed transparently as it nears expiry, so the cookie generally outlives any single access token. Setting a very short `maxAge` (under an hour) forces the cookie to be re-minted on nearly every request that can write cookies, which adds renewal overhead without a corresponding benefit. |

Both `audience` and `scope` must be permitted for anonymous callers on your tenant. An audience that is unresolved, or a resource server that does not allow anonymous access, produces `invalid_target`. A scope that is not granted to anonymous subjects produces `invalid_scope`. Both are thrown as `AnonymousSessionError` and are not recovered automatically.

### Overriding Routes

Two environment variables allow you to customize the feature routes:

```env
NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE=/auth/anonymous-session
NEXT_PUBLIC_ANONYMOUS_SESSION_LOGOUT_ROUTE=/auth/anonymous-session/logout
```

The routes are auto-mounted when the feature is enabled. They handle:

- **GET `/auth/anonymous-session`**: Retrieve the current session, with automatic token renewal
- **POST `/auth/anonymous-session/logout`**: Clear the anonymous session cookie

The paths above are the defaults. If you set any of these environment variables, every path in this document changes accordingly, including the ones the client-side examples fetch. The client examples below read the same environment variables so that they keep working when you override a route.

## Server-Side Usage

### Getting the Current Session

#### App Router (Server Components, Server Actions, Route Handlers)

Use the zero-argument form:

```typescript
import { auth0 } from "@/lib/auth0";

export default async function Page() {
  const session = await auth0.getAnonymousSession();

  if (session) {
    console.log(`Anonymous ID: ${session.id}`);
    console.log(`Token expires at: ${session.expiresAt}`);
    console.log(`Metadata:`, session.metadata);
  } else {
    console.log("No anonymous session");
  }

  return <div>...</div>;
}
```

The zero-argument form is a read. A Server Component cannot write cookies, so the SDK cannot persist a renewed token there and returns the stored session unchanged. If the access token has already expired, you receive it in that expired state, and `session.expiresAt` is in the past. Compare `session.expiresAt` against the current time before you use `session.accessToken`, and be ready to handle a 401 from the API you call. Renewal happens on the next request that reaches the `GET /auth/anonymous-session` route handler, which owns a writable response.

#### Pages Router (API Routes, `getServerSideProps`)

Pass the request object:

```typescript
import type { NextApiRequest, NextApiResponse } from "next";

import { auth0 } from "@/lib/auth0";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const session = await auth0.getAnonymousSession(req);

  if (session) {
    res.status(200).json(session);
  } else {
    res.status(204).end();
  }
}
```

#### Middleware

Pass the request object:

```typescript
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function middleware(req: NextRequest) {
  const session = await auth0.getAnonymousSession(req);

  if (session) {
    console.log(`Visitor ID: ${session.id}`);
  }

  return NextResponse.next();
}
```

The single-argument form is also a read. It takes a request but no response, so like the Server Component form it cannot persist a renewed token and returns the stored session unchanged, expired access token included.

**Return Value**: Returns `AnonymousSession | null`. It does not throw. It returns `null` when the feature is disabled, when no session cookie is present, and when the cookie cannot be decrypted or does not carry a usable anonymous access token.

**Token freshness**: Neither read form renews the access token, because neither has a response to write the refreshed cookie to. Both can therefore hand back an access token whose `expiresAt` has already passed. Treat `accessToken` as potentially stale in these contexts: check `expiresAt`, handle a 401 from the resource server, and route the visitor through the `GET /auth/anonymous-session` route handler (directly, or through the `useAnonymousSession` hook) when you need a token the SDK has renewed and persisted.

### Creating a New Session

Use `createAnonymousSession()` to generate a fresh anonymous session and persist it to the client. You can optionally provide metadata at creation time:

#### App Router (Server Actions, Route Handlers)

Use the zero-argument form:

```typescript
"use server";

import { AnonymousSessionError } from "@auth0/nextjs-auth0/errors";

import { auth0 } from "@/lib/auth0";

export async function startAnonymousSession(
  metadata?: Record<string, unknown>
) {
  try {
    const session = await auth0.createAnonymousSession({ metadata });
    return {
      success: true,
      id: session.id,
      expiresAt: session.expiresAt
    };
  } catch (error) {
    if (error instanceof AnonymousSessionError) {
      return { success: false, error: error.code };
    }
    throw error;
  }
}
```

Route Handler. The two-argument form writes the session cookie onto the response object you pass as `res`, so that object must be the one you return. Construct the response first, hand it to `createAnonymousSession`, then attach the JSON body to that same response by passing it as the second argument to `NextResponse.json`:

```typescript
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  const res = NextResponse.json(null, { status: 201 });

  try {
    // Optionally parse metadata from the request body
    const body = (await req.json().catch(() => ({}))) ?? {};
    const session = await auth0.createAnonymousSession(req, res, {
      metadata: body.metadata
    });
    // `res` now carries the Set-Cookie header. Reusing it as the response init
    // copies that header, and the status, onto the response with the body.
    return NextResponse.json(session, res);
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to create anonymous session" },
      { status: 500 }
    );
  }
}
```

Do not pass a throwaway response as `res` and then return a different one. The `Set-Cookie` header is written onto the object you pass, so a different response reaches the browser without the cookie, and the visitor never gets an anonymous session. If you would rather build the final response yourself, copy the cookies across explicitly:

```typescript
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  const carrier = NextResponse.json(null);
  const body = (await req.json().catch(() => ({}))) ?? {};
  const session = await auth0.createAnonymousSession(req, carrier, {
    metadata: body.metadata
  });

  const res = NextResponse.json(session, { status: 201 });
  for (const cookie of carrier.cookies.getAll()) {
    res.cookies.set(cookie);
  }
  return res;
}
```

#### Pages Router (API Routes)

`createAnonymousSession` writes cookies through a `NextResponse` cookie jar, which a Pages Router `NextApiResponse` does not have. Pass a `NextResponse` as the carrier, then copy its `Set-Cookie` headers onto the API response:

```typescript
import type { NextApiRequest, NextApiResponse } from "next";
import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    return res.status(405).end();
  }

  try {
    const carrier = new NextResponse();
    const body = req.body ?? {};
    const session = await auth0.createAnonymousSession(req, carrier, {
      metadata: body.metadata
    });

    for (const cookie of carrier.headers.getSetCookie()) {
      res.appendHeader("set-cookie", cookie);
    }

    res.status(201).json(session);
  } catch (error) {
    res.status(500).json({ error: "Failed to create anonymous session" });
  }
}
```

Reading the session in the Pages Router needs no carrier, because `getAnonymousSession(req)` does not write cookies.

**Return Value**: Returns `AnonymousSession`. It never returns `null`. It throws `AnonymousSessionError` when:

- The feature is disabled in your configuration. The code is `unauthorized_client` and no network call is made.
- Your client is not enabled for anonymous sessions on the tenant, or the tenant feature flag is off.
- The authorization server rejects the request or reports an error.

## Client-Side Usage

### The `useAnonymousSession` Hook

The `useAnonymousSession` hook (client-only) fetches and caches the anonymous session using SWR, mirroring the `useUser()` pattern:

```typescript
"use client";

import { useAnonymousSession } from "@auth0/nextjs-auth0/client";

export function MyComponent() {
  const { anonymous, isLoading, error, invalidate } = useAnonymousSession();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>Error: {error.message}</div>;
  }

  if (!anonymous) {
    return <div>No anonymous session</div>;
  }

  return (
    <div>
      <p>ID: {anonymous.id}</p>
      <p>Token expires: {new Date(anonymous.expiresAt * 1000).toISOString()}</p>
      <p>Metadata: {JSON.stringify(anonymous.metadata)}</p>
      <button onClick={() => invalidate()}>Refresh</button>
    </div>
  );
}
```

The hook fetches through the anonymous session route, which does renew an expired access token and persist it, so `anonymous.accessToken` from the hook is fresh.

#### Hook Options

| Option  | Type     | Default                   | Description                                                                                                                                                                                                     |
| ------- | -------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `route` | `string` | `/auth/anonymous-session` | Endpoint to fetch the session from. When omitted, the hook reads `NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE` and falls back to `/auth/anonymous-session`. The resolved path is prefixed with `NEXT_PUBLIC_BASE_PATH`. |

#### Hook Return Value

| Field        | Type                       | Description                                                                                                    |
| ------------ | -------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `anonymous`  | `AnonymousSession \| null` | The current session. `null` while loading, when the route returns 204 because no session exists, and on error. |
| `isLoading`  | `boolean`                  | `true` while the session is being fetched. `false` once data or an error is available.                         |
| `error`      | `Error \| null`            | Any fetch error, or `null` if successful.                                                                      |
| `invalidate` | `() => void`               | Trigger SWR revalidation, for example after a metadata update.                                                 |

### Provider Seeding

When you fetch the anonymous session server-side (e.g., in `getServerSideProps` or a Server Component), pass it to `Auth0Provider` to avoid a loading flash in the browser:

```typescript
import { Auth0Provider } from "@auth0/nextjs-auth0/client";
import { auth0 } from "@/lib/auth0";

export default async function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  const anonymous = await auth0.getAnonymousSession();

  return (
    <Auth0Provider anonymousSession={anonymous}>
      {children}
    </Auth0Provider>
  );
}
```

The seed value comes from a read context, so its `accessToken` may already be expired. It is safe to use for rendering the identity and the metadata without a flash. Do not send a seeded `accessToken` to an API before SWR has revalidated. The `anonymousSessionRoute` prop and the hook's `route` option must resolve to the same path, otherwise the seed lands under a different SWR cache key and the hook fetches anyway.

The `Auth0Provider` accepts:

| Prop                    | Type                                    | Description                                                                                                                                                      |
| ----------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `anonymousSession`      | `AnonymousSession \| null \| undefined` | Initial session data to seed the SWR cache. Prevents a loading flash. Pass `undefined` to leave the cache unseeded; `null` seeds an explicit "no session" state. |
| `anonymousSessionRoute` | `string`                                | Route for the anonymous session endpoint. When omitted, the provider reads `NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE` and falls back to `/auth/anonymous-session`.    |

## Working with Metadata

Metadata is an optional key-value object (up to 1 KB) that you can attach to an anonymous session when you create it. Once set, metadata is immutable. It persists across token renewals but cannot be updated without creating a new session.

To create a session with metadata, pass the `metadata` option to `createAnonymousSession()`:

```typescript
"use server";

import { auth0 } from "@/lib/auth0";

export async function startAnonymousSession() {
  const session = await auth0.createAnonymousSession({
    metadata: {
      theme: "dark",
      language: "es",
      preferences: { newsletter: true }
    }
  });

  return session;
}
```

The SDK validates that `metadata` is a plain JSON object and that its serialized UTF-8 byte length does not exceed 1 KB before making the network call. If either check fails, `createAnonymousSession()` throws `invalid_request` or `metadata_too_large` without reaching the authorization server.

Metadata is readable server-side from the session object returned by `getAnonymousSession()`. Because metadata cannot be updated, there is no server-side write method. To change metadata, create a new anonymous session with the updated values and clear the old one.

## Logging Out

To end an anonymous session and clear the cookie, call the logout route. The example reads `NEXT_PUBLIC_ANONYMOUS_SESSION_LOGOUT_ROUTE` so that it keeps working if you override the route:

```typescript
"use client";

const LOGOUT_ROUTE =
  process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_LOGOUT_ROUTE ||
  "/auth/anonymous-session/logout";

async function logoutAnonymous() {
  const response = await fetch(LOGOUT_ROUTE, { method: "POST" });

  if (!response.ok) {
    throw new Error("Failed to log out of the anonymous session");
  }

  // Session cleared; you may want to reset app state
  window.location.reload();
}
```

The logout route clears the anonymous session cookie from your application, including any chunk cookies, and responds with 200 and the body `{"ok":true}`. It is idempotent: calling it with no active session succeeds the same way.

**Important:** Logout clears only the local session cookie. Access tokens already issued to the anonymous identity remain valid until they naturally expire. There is no server-side revocation mechanism for anonymous sessions, so a token that was minted before logout can still be used to call your APIs until its expiration time passes. Treat anonymous sessions as suitable for non-sensitive personalization and preferences, not for access control.

## Error Handling

Errors related to anonymous sessions are represented by `AnonymousSessionError`, which includes a `code` field:

```typescript
import { AnonymousSessionError } from "@auth0/nextjs-auth0/errors";

import { auth0 } from "@/lib/auth0";

try {
  const session = await auth0.createAnonymousSession();
} catch (error) {
  if (error instanceof AnonymousSessionError) {
    switch (error.code) {
      case "feature_not_enabled":
        console.error("Anonymous sessions are not enabled on your tenant");
        break;
      case "unauthorized_client":
        console.error(
          "Anonymous sessions are disabled in your SDK configuration, " +
            "or this client is not enabled for them on the tenant"
        );
        break;
      case "invalid_target":
        console.error(
          "The configured anonymousSession.audience is unresolved, or that " +
            "API does not allow anonymous access"
        );
        break;
      case "invalid_scope":
        console.error(
          "The configured anonymousSession.scope is not granted to anonymous subjects"
        );
        break;
      case "metadata_too_large":
        console.error("Metadata exceeds 1 KB limit when creating the session");
        break;
      case "invalid_request":
        console.error("Request was malformed");
        break;
      default:
        console.error(`Anonymous session error: ${error.code}`);
    }
  } else {
    throw error;
  }
}
```

`error.message` carries the `error_description` the authorization server returned whenever one is present, and falls back to a built-in message for the code otherwise. The same server wording is also available unmodified on `error.description`, and the raw upstream body or original error on `error.cause`. Log `error.code` together with `error.description` (or `error.message`) and `error.cause` when diagnosing a tenant configuration problem.

### Error Codes and HTTP Status

| Code                    | HTTP Status | Recovery | Description                                                                                                                                                           |
| ----------------------- | ----------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_client`        | 401         | Manual   | Client authentication failed. Check your client credentials.                                                                                                          |
| `feature_not_enabled`   | 403         | Manual   | Anonymous sessions are not enabled on your Auth0 tenant.                                                                                                              |
| `unauthorized_client`   | 403         | Manual   | Anonymous sessions are disabled in your SDK configuration, or your application is not enabled for anonymous sessions on the tenant.                                   |
| `server_error`          | 500         | Retry    | Authorization server encountered an error.                                                                                                                            |
| `invalid_session_token` | 400         | Auto     | Session token is invalid or expired. During renewal, a new session is created silently.                                                                               |
| `session_expired`       | 400         | Auto     | Session expired. During renewal, a new session is created silently.                                                                                                   |
| `metadata_too_large`    | 400         | Manual   | Metadata payload exceeds the 1 KB UTF-8 byte limit when creating a session.                                                                                           |
| `invalid_target`        | 400         | Manual   | The `anonymousSession.audience` you configured is unresolved, or that resource server does not allow anonymous access. Reachable only when you configure an audience. |
| `invalid_scope`         | 400         | Manual   | The `anonymousSession.scope` you configured is not granted to anonymous subjects. Reachable only when you configure a scope.                                          |
| `invalid_request`       | 400         | Manual   | Request was malformed, or `metadata` is not a plain JSON object when creating a session.                                                                              |

**Auto-Recovery**: When `session_expired` or `invalid_session_token` errors occur during token renewal, the SDK silently creates a new session and returns it, avoiding application errors. No error is thrown. The metadata on the old session is lost permanently.

## Security and Limitations

### Security Considerations

#### Logout does not revoke tokens

Calling the logout route clears the local `auth0_anon` cookie but does NOT revoke the session token or any access tokens that have already been issued. Anonymous sessions are stateless on the Auth0 platform. There is no server-side revocation mechanism. Tokens issued before logout remain valid until their natural expiration.

For security-sensitive use cases that require immediate token revocation, use standard authenticated sessions with refresh tokens. For anonymous sessions, keep token TTLs short and treat the session token as a sensitive credential.

#### Silent session recreation loses metadata

When the anonymous session's access token cannot be renewed because the underlying session expired or the session token became invalid (`session_expired` or `invalid_session_token`), the SDK silently creates a new anonymous session rather than throwing an error. This behavior upholds the read contract: a Server Component read of the anonymous session never breaks a render.

This silent recreation has important consequences. First, the anonymous identity changes. A new `anon@{uuid}` subject is issued. Second, any metadata set on the previous session is not carried over and is lost.

Do not store security-critical or authorization-relevant data in anonymous session metadata. Treat metadata as ephemeral. If your application depends on specific metadata values, re-set them after a recreation.

#### Token trust model

Anonymous access tokens are fetched server-to-server from Auth0 over TLS and are trusted on that basis. The SDK does not independently verify the access token signature. This is consistent with standard token handling practices. The SDK validates that the token response's `expires_in` value is within sane bounds.

#### Session linking and fixation protection

When a user logs in while an anonymous session cookie is present, the SDK attempts to link the anonymous session to the authenticated session. The SDK sets `ctx.anonymousSessionLinked` in the `onCallback` context to indicate whether the linkage succeeded.

The flag is `true` only if the anonymous cookie present at callback matches the one that was bound at login initiation. This is a session-fixation protection. If the cookie changed between login and callback, the flag is `false`.

Applications that perform linking SHOULD check this flag in `onCallback`. Do not treat the anonymous session as linked when the flag is `false`.

### The session token travels in the authorization request URL

Read this before you enable the feature.

When an anonymous session is active and the visitor starts a login, the SDK links the two by adding the anonymous `session_token` to the request it sends to Auth0's `/authorize` endpoint. Unless you have enabled Pushed Authorization Requests, that request is a browser redirect, so the session token is carried as a query parameter in a URL the browser navigates to. A URL the browser navigates to is not private. The session token consequently becomes visible in:

- The `Location` header of the redirect the SDK returns, and any proxy or log that records response headers.
- The visitor's browser history, where it persists after the browser is closed.
- The `Referer` header sent by the Auth0 login page to any third-party resource it loads, subject to that page's referrer policy.
- Auth0's own access logs for the `/authorize` request, and the logs of any intermediary in front of it.

The session token is a long-lived handle. Anyone who obtains it can mint access tokens for that anonymous identity and read that session's metadata until the session expires. Do not put anything in anonymous session metadata that you would not accept being exposed through one of the channels above.

These mitigations are in place and are the ones you can rely on:

- **The injected token can only come from your own cookie.** `session_token` is on the SDK's reserved authorization-parameter list, so a value supplied by a caller through a login query string or through `authorizationParameters` is dropped before the request is built. The only token the SDK will send is the one it decrypted out of its own `HttpOnly` app-domain cookie for that browser. An attacker cannot use the login endpoint to plant a session token they already know.
- **The token is never readable by client-side JavaScript.** The cookie that holds it is encrypted with AES-256-GCM under a key derived from your `secret`, and is set `HttpOnly`. Only the access token reaches the browser, through the anonymous session route.
- **The anonymous session route responses are not cacheable.** Every response from the three anonymous session routes carries `Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0`, so a shared cache cannot retain a session payload and serve it to another visitor.
- **The login-to-callback binding is single-use.** The linkage is recorded in the encrypted, state-keyed transaction cookie, which the SDK deletes when the callback completes and which expires after one hour regardless. A replayed callback finds no transaction and is rejected.

You can keep the session token out of the redirect URL entirely by enabling Pushed Authorization Requests on your tenant and setting `pushedAuthorizationRequests: true`. The SDK then posts the authorization parameters to Auth0 server-to-server and redirects the browser to a URL that carries only a `request_uri` and your `client_id`. The session token never enters the address bar, the history, or the `Referer` header. This requires PAR support on your Auth0 tenant.

### Other security properties

- **Cookie attributes.** The anonymous session cookie is `HttpOnly` and `Path=/`. `SameSite` defaults to `lax` and `Secure` defaults to `true`; both are configurable. Setting `secure: false` sends the cookie over plain HTTP and is only appropriate for local development.
- **The session token is not an API credential.** Send `accessToken` to your APIs. The session token is a renewal and metadata handle, is not accepted as a bearer token, and never leaves the server except in the authorization request described above.
- **Large sessions are split across cookies.** Metadata that pushes the encrypted payload past the single-cookie size limit is chunked across `<cookie-name>__0`, `<cookie-name>__1`, and so on, using the same mechanism as the authenticated session cookie. For the default cookie name `auth0_anon`, these are `auth0_anon__0`, `auth0_anon__1`, and so on. Logout clears the chunks along with the base cookie.

### Known Limitations

The following are not in scope for this release:

- **Cross-App SSO**: The anonymous session lives in an app-domain cookie and does not participate in Auth0 cross-app single sign-on.
- **Password Reset Preservation**: Anonymous sessions are not carried forward during password resets. Users complete the reset and start a new session.
- **Sessions During Interactive Login**: Completing a login does not clear the anonymous cookie. The two sessions coexist until you end the anonymous one yourself. Use the `anonymousSessionLinked` flag on the `onCallback` context to decide what to do.
- **No server-side revocation**: Logging out of an anonymous session clears the cookie. Access tokens already issued to that identity remain valid until they expire.
- **DPoP**: Auth0 does not support anonymous sessions for clients configured for DPoP. The SDK does not block the combination, so a DPoP client that enables anonymous sessions receives an error from the authorization server rather than a configuration error at startup.

### Compatibility

Anonymous sessions are independent from authenticated sessions and do not interfere with existing login and logout flows. The feature is entirely opt-in. When `anonymousSession.enabled` is `false` or the configuration block is absent, the three routes return 404, `getAnonymousSession()` returns `null`, and `createAnonymousSession()` throws `AnonymousSessionError` with code `unauthorized_client`.

## Type Reference

### `AnonymousSession`

```typescript
interface AnonymousSession {
  /** Anonymous subject, format: "anon@{uuid}" */
  id: string;
  /** Bearer token for API calls */
  accessToken: string;
  /** Unix seconds when accessToken expires */
  expiresAt: number;
  /** User-defined metadata (optional, max 1 KB) */
  metadata?: Record<string, unknown>;
}
```

### `AnonymousSessionError`

Exported from `@auth0/nextjs-auth0/errors`. It extends the SDK's `SdkError` base class, which extends `Error`.

```typescript
class AnonymousSessionError extends SdkError {
  /** Error code from the authorization server or from SDK validation */
  code: string;
  /**
   * A human-readable message. Set to the error_description returned by the
   * authorization server when one is present, otherwise a built-in message for
   * the code.
   */
  message: string;
  /**
   * The raw error_description reported by the authorization server, when one was
   * present. Undefined for errors the SDK raises locally (for example
   * metadata_too_large). Prefer this over message when you need the server's
   * exact wording for logging or diagnostics.
   */
  description?: string;
  /**
   * The underlying cause: the raw error body from the authorization server, or
   * the original error the SDK caught. Undefined when there is no upstream
   * cause. Inspect it when message and code do not explain the failure.
   */
  cause?: unknown;
}
```

Read `description` and `cause` alongside `code` when diagnosing a tenant configuration problem. `description` carries the authorization server's exact wording (which audience was rejected, which scope was refused), and `cause` holds the raw upstream body or the original error the SDK caught.

### `UseAnonymousSessionOptions`

```typescript
interface UseAnonymousSessionOptions {
  /** Custom route for the anonymous session endpoint */
  route?: string;
}
```

### `AnonymousSessionConfig`

```typescript
interface AnonymousSessionConfig {
  /** Enable the feature */
  enabled: boolean;
  /**
   * API identifier the anonymous access token is issued for. Sent on create and
   * on every renewal. When omitted, the authorization server issues the token
   * for the tenant default audience.
   */
  audience?: string;
  /**
   * Space-separated scopes requested for the anonymous access token. Sent on
   * create and on every renewal. When omitted, no scope is requested and the
   * authorization server applies the tenant default.
   */
  scope?: string;
  cookie?: {
    /** Cookie name (default: "auth0_anon") */
    name?: string;
    /** SameSite attribute (default: "lax") */
    sameSite?: "lax" | "strict" | "none";
    /** Secure flag (default: true) */
    secure?: boolean;
    /** Cookie max age in seconds (default: 2592000, 30 days) */
    maxAge?: number;
  };
}
```

## Examples

### Full-Page Anonymous Session Setup

```typescript
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  anonymousSession: {
    enabled: true
  }
});
```

```typescript
// app/layout.tsx
import { Auth0Provider } from "@auth0/nextjs-auth0/client";
import { auth0 } from "@/lib/auth0";

export default async function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  const anonymous = await auth0.getAnonymousSession();

  return (
    <Auth0Provider anonymousSession={anonymous}>
      <html>
        <body>{children}</body>
      </html>
    </Auth0Provider>
  );
}
```

```typescript
// app/page.tsx
"use client";

import { useAnonymousSession } from "@auth0/nextjs-auth0/client";

export default function Home() {
  const { anonymous, isLoading } = useAnonymousSession();

  if (isLoading) return <div>Loading...</div>;
  if (!anonymous) return <div>No session</div>;

  return (
    <div>
      <h1>Welcome, {anonymous.id}</h1>
      <p>Your metadata: {JSON.stringify(anonymous.metadata)}</p>
    </div>
  );
}
```

### Creating a Session on First Visit

```typescript
"use client";

import { useEffect, useState } from "react";
import { useAnonymousSession } from "@auth0/nextjs-auth0/client";

export function FirstVisitSetup() {
  const { anonymous, invalidate } = useAnonymousSession();
  const [isCreating, setIsCreating] = useState(false);

  const createSession = async () => {
    setIsCreating(true);
    try {
      const response = await fetch("/api/anonymous/create", { method: "POST" });
      if (response.ok) {
        invalidate();
      }
    } finally {
      setIsCreating(false);
    }
  };

  if (anonymous) {
    return <div>Session active: {anonymous.id}</div>;
  }

  return (
    <button onClick={createSession} disabled={isCreating}>
      {isCreating ? "Creating..." : "Get Started"}
    </button>
  );
}
```

```typescript
// app/api/anonymous/create/route.ts
import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  // Build the response first. createAnonymousSession writes the session cookie
  // onto this object, so this object has to be the one that is returned.
  const res = NextResponse.json(null, { status: 201 });

  try {
    const session = await auth0.createAnonymousSession(req, res);
    return NextResponse.json(session, res);
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to create session" },
      { status: 500 }
    );
  }
}
```

### Storing User Preferences

Because metadata is set once at session creation and cannot be updated, you must create a new session to change preferences:

```typescript
"use client";

import { useAnonymousSession } from "@auth0/nextjs-auth0/client";
import { useState } from "react";

export function PreferencesForm() {
  const { anonymous, invalidate } = useAnonymousSession();
  const [theme, setTheme] = useState(
    (anonymous?.metadata?.theme as string) || "light"
  );

  const handleSave = async () => {
    // Create a new session with updated metadata
    const response = await fetch("/api/anonymous/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        metadata: { theme, savedAt: new Date().toISOString() }
      })
    });

    if (response.ok) {
      invalidate();
      alert("Preferences saved");
    }
  };

  return (
    <div>
      <select value={theme} onChange={(e) => setTheme(e.target.value)}>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      <button onClick={handleSave}>Save</button>
    </div>
  );
}
```
