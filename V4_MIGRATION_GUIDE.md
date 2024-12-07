# V4 Migration Guide

Guide to migrating from `3.x` to `4.x`.

## Environment variables

The following environment variables are required in v4:

```
AUTH0_DOMAIN
AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET
AUTH0_SECRET
APP_BASE_URL
```

Of the required variables, the following have changed from v3:

- `AUTH0_BASE_URL` has been renamed to `APP_BASE_URL` (e.g.: `http://localhost:3000`)
- `AUTH0_ISSUER_BASE_URL` has been renamed to `AUTH0_DOMAIN` and does **not** accept a scheme (e.g.: `example.us.auth0.com`)

All other configuration must be specified via the `Auth0Client` constructor.

## Routes

Previously, it was required to set up a dynamic Route Handler to mount the authentication endpoints to handle requests.

For example, in v3 when using the App Router, you were required to create a Route Handler, under `/app/api/auth/[auth0]/route.ts`, with the following contents:

```ts
import { handleAuth } from "@auth0/nextjs-auth0"

export const GET = handleAuth()
```

In v4, the routes are now mounted automatically by the middleware:

```ts
import type { NextRequest } from "next/server"

import { auth0 } from "./lib/auth0"

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request)
}
```

For a complete example, see [the Getting Started section](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#getting-started).

Additionally, in v4, the mounted routes drop the `/api` prefix. For example, the default login route is now `/auth/login` instead of `/api/auth/login`. To link to the login route, it would now be: `<a href="/auth/login">Log in</a>`.

> [!NOTE]  
> If you are using an existing client, you will need to update your **Allowed Callback URLs** accordingly.

The complete list of routes mounted by the SDK can be found [here](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#routes).

## Auth0 middleware

In v4, the Auth0 middleware is a central component of the SDK. It serves a number of core functions such as registering the required authentication endpoints, providing rolling sessions functionality, keeping access tokens fresh, etc.

When configuring your application to use v4 of the SDK, it is now **required** to mount the middleware:

```ts
// middleware.ts

import type { NextRequest } from "next/server"

import { auth0 } from "./lib/auth0"

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request)
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
}
```

See [the Getting Started section](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#getting-started) for details on how to configure the middleware.

### Protecting routes

By default, **the middleware does not protect any routes**. To protect a page, you can use the `getSession()` handler in the middleware, like so:

```ts
export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  // authentication routes — let the middleware handle it
  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const { origin } = new URL(request.url)
  const session = await auth0.getSession()

  // user does not have a session — redirect to login
  if (!session) {
    return NextResponse.redirect(`${origin}/auth/login`)
  }

  return authRes
}
```

> [!NOTE]  
> We recommend keeping the security checks as close as possible to the data source you're accessing. This is also in-line with [the recommendations from the Next.js team](https://nextjs.org/docs/app/building-your-application/authentication#optimistic-checks-with-middleware-optional).

## `<UserProvider />`

The `<UserProvider />` has been renamed to `<Auth0Provider />`.

Previously, when setting up your application to use v3 of the SDK, it was required to wrap your layout in the `<UserProvider />`. **This is no longer required by default.**

If you would like to pass an initial user during server rendering to be available to the `useUser()` hook, you can wrap your components with the new `<Auth0Provider />` ([see example](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#auth0provider-)).

## Rolling sessions

In v4, rolling sessions are enabled by default and are handled automatically by the middleware with no additional configuration required.

See the [session configuration section](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#session-configuration) for additional details on how to configure it.

## `withPageAuthRequired` and `withApiAuthRequired`

`withPageAuthRequired` and `withApiAuthRequired` have been removed from v4 of the SDK. Instead, we recommend adding a `getSession()` check or relying on `useUser()` hook where you would have previously used the helpers.

On the server-side, the `getSession()` method can be used to check if the user is authenticated:

```tsx
function Page() {
  const session = await getSession()

  if (!session) {
    // the user will be redirected to authenticate and then taken to the
    // /dashboard route after successfully being authenticated
    return redirect('/auth/login?returnTo=/dashboard')
  }

  return <h1>Hello, {session.user.name}</h1>
}
```

The `getSession()` method can be used in the App Router in Server Components, Server Routes (APIs), Server Actions, and middleware.

In the Pages Router, the `getSession(req)` method takes a request object and can be used in `getServerSideProps`, API routes, and middleware.

Read more about [accessing the authenticated user here](https://github.com/guabu/nextjs-auth0/tree/v4?tab=readme-ov-file#accessing-the-authenticated-user).

In the browser, you can rely on the `useUser()` hook to check if the user is authenticated. For example:

```tsx
"use client"

import { useUser } from "@auth0/nextjs-auth0"

export default function Profile() {
  const { user, isLoading, error } = useUser()

  if (isLoading) return <div>Loading...</div>
  if (!user) return <div>Not authenticated!</div>

  return (
    <main>
      <h1>Profile</h1>
      <div>
        <pre>{JSON.stringify(user, null, 2)}</pre>
      </div>
    </main>
  )
}
```

## Passing custom authorization parameters

In v3, custom authorization parameters required specifying a custom handler, like so:

```ts
import { handleAuth, handleLogin } from "@auth0/nextjs-auth0"

export default handleAuth({
  login: handleLogin({
    authorizationParams: { audience: "urn:my-api" },
  }),
})
```

In v4, you can simply append the authorization parameters to the query parameter of the login endpoint and they will be automatically fowarded to the `/authorize` endpoint, like so:

```html
<a href="/auth/login?audience=urn:my-api">Login</a>
```

Or alternatively, it can be statically configured when initializing the SDK, like so:

```ts
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
})
```

Read more about [passing authorization parameters](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#passing-authorization-parameters).

## ID token claims

In v3, any claims added to the ID token were automatically propagated to the `user` object in the session. This resulted in the large cookies that exceeded browser limits.

In v4, by default, the only claims that are persisted in the `user` object of session are:

- `sub`
- `name`
- `nickname`
- `given_name`
- `family_name`
- `picture`
- `email`
- `email_verified`
- `org_id`

If you'd like to customize the `user` object to include additional custom claims from the ID token, you can use the `beforeSessionSaved` hook (see [beforeSessionSaved hook](https://github.com/guabu/nextjs-auth0/tree/v4?tab=readme-ov-file#beforesessionsaved))

## Additional changes

- By default, v4 is edge-compatible and as such there is no longer a `@auth0/nextjs-auth0/edge` export.
- Cookie chunking has been removed
  - If the cookie size exceeds the browser limit of 4096 bytes, a warning will be logged
  - To store large session data, please use a [custom data store](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#database-sessions) with a SessionStore implementation
- All cookies set by the SDK default to `SameSite=Lax`
- `touchSession` method was removed. The middleware enables rolling sessions by default and can be configured via the [session configuration](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file#session-configuration).
- `updateSession` method was removed.
- `getAccessToken` can now be called in React Server Components.
