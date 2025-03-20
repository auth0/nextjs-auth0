# Examples

- [Passing authorization parameters](#passing-authorization-parameters)
- [The `returnTo` parameter](#the-returnto-parameter)
  - [Redirecting the user after authentication](#redirecting-the-user-after-authentication)
  - [Redirecting the user after logging out](#redirecting-the-user-after-logging-out)
- [Accessing the authenticated user](#accessing-the-authenticated-user)
  - [In the browser](#in-the-browser)
  - [On the server (App Router)](#on-the-server-app-router)
  - [On the server (Pages Router)](#on-the-server-pages-router)
  - [Middleware](#middleware)
- [Updating the session](#updating-the-session)
  - [On the server (App Router)](#on-the-server-app-router-1)
  - [On the server (Pages Router)](#on-the-server-pages-router-1)
  - [Middleware](#middleware-1)
- [Getting an access token](#getting-an-access-token)
  - [In the browser](#in-the-browser-1)
  - [On the server (App Router)](#on-the-server-app-router-2)
  - [On the server (Pages Router)](#on-the-server-pages-router-2)
  - [Middleware](#middleware-2)
- [`<Auth0Provider />`](#auth0provider-)
  - [Passing an initial user from the server](#passing-an-initial-user-from-the-server)
- [Hooks](#hooks)
  - [`beforeSessionSaved`](#beforesessionsaved)
  - [`onCallback`](#oncallback)
- [Session configuration](#session-configuration)
- [Database sessions](#database-sessions)
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

## Passing authorization parameters

There are 2 ways to customize the authorization parameters that will be passed to the `/authorize` endpoint. The first option is through static configuration when instantiating the client, like so:

```ts
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: "openid profile email",
    audience: "urn:custom:api",
  },
})
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

For example: `/auth/login?returnTo=https://example.com/some-page` would redirect the user to the `https://example.com/some-page` URL after they have logged out.

> [!NOTE]  
> The URL specified as `returnTo` parameters must be registered in your client's **Allowed Logout URLs**.

## Accessing the authenticated user

### In the browser

To access the currently authenticated user on the client, you can use the `useUser()` hook, like so:

```tsx
"use client"

import { useUser } from "@auth0/nextjs-auth0"

export default function Profile() {
  const { user, isLoading, error } = useUser()

  if (isLoading) return <div>Loading...</div>

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

### On the server (App Router)

On the server, the `getSession()` helper can be used in Server Components, Server Routes, and Server Actions to get the session of the currently authenticated user and to protect resources, like so:

```tsx
import { auth0 } from "@/lib/auth0"

export default async function Home() {
  const session = await auth0.getSession()

  if (!session) {
    return <div>Not authenticated</div>
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}!</h1>
    </main>
  )
}
```

### On the server (Pages Router)

On the server, the `getSession(req)` helper can be used in `getServerSideProps` and API routes to get the session of the currently authenticated user and to protect resources, like so:

```tsx
import type { GetServerSideProps, InferGetServerSidePropsType } from "next"

import { auth0 } from "@/lib/auth0"

export const getServerSideProps = (async (ctx) => {
  const session = await auth0.getSession(ctx.req)

  if (!session) return { props: { user: null } }

  return { props: { user: session.user ?? null } }
}) satisfies GetServerSideProps<{ user: any | null }>

export default function Page({
  user,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  if (!user) {
    return (
      <main>
        <p>Not authenticated!</p>
      </main>
    )
  }

  return (
    <main>
      <p>Welcome, {user.name}!</p>
    </main>
  )
}
```

### Middleware

In middleware, the `getSession(req)` helper can be used to get the session of the currently authenticated user and to protect resources, like so:

```ts
import { NextRequest, NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const session = await auth0.getSession(request)

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(new URL("/auth/login", request.nextUrl.origin))
  }

  // the headers from the auth middleware should always be returned
  return authRes
}
```

> [!IMPORTANT]  
> The `request` object must be passed as a parameter to the `getSession(request)` method when called from a middleware to ensure that any updates to the session can be read within the same request.

## Updating the session

The `updateSession` method could be used to update the session of the currently authenticated user in the App Router, Pages Router, and middleware. If the user does not have a session, an error will be thrown.

> [!NOTE]
> Any updates to the session will be overwritten when the user re-authenticates and obtains a new session.

### On the server (App Router)

On the server, the `updateSession()` helper can be used in Server Routes and Server Actions to update the session of the currently authenticated user, like so:

```tsx
import { NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function GET() {
  const session = await auth0.getSession()

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  await auth0.updateSession({
    ...session,
    updatedAt: Date.now(),
  })

  return NextResponse.json(null, { status: 200 })
}
```

> [!NOTE]
> The `updateSession()` method is not usable in Server Components as it is not possible to write cookies.

### On the server (Pages Router)

On the server, the `updateSession(req, res, session)` helper can be used in `getServerSideProps` and API routes to update the session of the currently authenticated user, like so:

```tsx
import type { NextApiRequest, NextApiResponse } from "next"

import { auth0 } from "@/lib/auth0"

type ResponseData =
  | {}
  | {
      error: string
    }

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ResponseData>
) {
  const session = await auth0.getSession(req)

  if (!session) {
    return res.status(401).json({ error: "Unauthorized" })
  }

  await auth0.updateSession(req, res, {
    ...session,
    updatedAt: Date.now(),
  })

  res.status(200).json({})
}
```

### Middleware

In middleware, the `updateSession(req, res, session)` helper can be used to update the session of the currently authenticated user, like so:

```ts
import { NextRequest, NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const session = await auth0.getSession(request)

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(new URL("/auth/login", request.nextUrl.origin))
  }

  await auth0.updateSession(request, authRes, {
    ...session,
    user: {
      ...session.user,
      // add custom user data
      updatedAt: Date.now(),
    },
  })

  // the headers from the auth middleware should always be returned
  return authRes
}
```

> [!IMPORTANT]  
> The `request` and `response` objects must be passed as a parameters to the `updateSession(request, response, session)` method when called from a middleware to ensure that any updates to the session can be read within the same request.

If you are using the Pages Router and need to read updates to the session made in the middleware within the same request, you will need to ensure that any updates to the session are propagated on the request object, like so:

```ts
import { NextRequest, NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const session = await auth0.getSession(request)

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(new URL("/auth/login", request.nextUrl.origin))
  }

  await auth0.updateSession(request, authRes, {
    ...session,
    user: {
      ...session.user,
      // add custom user data
      updatedAt: Date.now(),
    },
  })

  // create a new response with the updated request headers
  const resWithCombinedHeaders = NextResponse.next({
    request: {
      headers: request.headers,
    },
  })

  // set the response headers (set-cookie) from the auth response
  authRes.headers.forEach((value, key) => {
    resWithCombinedHeaders.headers.set(key, value)
  })

  // the headers from the auth middleware should always be returned
  return resWithCombinedHeaders
}
```

## Getting an access token

The `getAccessToken()` helper can be used both in the browser and on the server to obtain the access token to call external APIs. If the access token has expired and a refresh token is available, it will automatically be refreshed and persisted.

### In the browser

To obtain an access token to call an external API on the client, you can use the `getAccessToken()` helper, like so:

```tsx
"use client"

import { getAccessToken } from "@auth0/nextjs-auth0"

export default function Component() {
  async function fetchData() {
    try {
      const token = await getAccessToken()
      // call external API with token...
    } catch (err) {
      // err will be an instance of AccessTokenError if an access token could not be obtained
    }
  }

  return (
    <main>
      <button onClick={fetchData}>Fetch Data</button>
    </main>
  )
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
import { NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function GET() {
  try {
    const token = await auth0.getAccessToken()
    // call external API with token...
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  return NextResponse.json({
    message: "Success!",
  })
}
```

### On the server (Pages Router)

On the server, the `getAccessToken(req, res)` helper can be used in `getServerSideProps` and API routes to get an access token to call external APIs, like so:

```ts
import type { NextApiRequest, NextApiResponse } from "next"

import { auth0 } from "@/lib/auth0"

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<{ message: string }>
) {
  try {
    const token = await auth0.getAccessToken(req, res)
    // call external API with token...
  } catch (err) {
    // err will be an instance of AccessTokenError if an access token could not be obtained
  }

  res.status(200).json({ message: "Success!" })
}
```

### Middleware

In middleware, the `getAccessToken(req, res)` helper can be used to get an access token to call external APIs, like so:

```tsx
import { NextRequest, NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const session = await auth0.getSession(request)

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(new URL("/auth/login", request.nextUrl.origin))
  }

  const accessToken = await auth0.getAccessToken(request, authRes)

  // the headers from the auth middleware should always be returned
  return authRes
}
```

> [!IMPORTANT]  
> The `request` and `response` objects must be passed as a parameters to the `getAccessToken(request, response)` method when called from a middleware to ensure that the refreshed access token can be accessed within the same request.

If you are using the Pages Router and are calling the `getAccessToken` method in both the middleware and an API Route or `getServerSideProps`, it's recommended to propagate the headers from the middleware, as shown below. This will ensure that calling `getAccessToken` in the API Route or `getServerSideProps` will not result in the access token being refreshed again.

```ts
import { NextRequest, NextResponse } from "next/server"

import { auth0 } from "@/lib/auth0"

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request)

  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authRes
  }

  const session = await auth0.getSession(request)

  if (!session) {
    // user is not authenticated, redirect to login page
    return NextResponse.redirect(new URL("/auth/login", request.nextUrl.origin))
  }

  const accessToken = await auth0.getAccessToken(request, authRes)

  // create a new response with the updated request headers
  const resWithCombinedHeaders = NextResponse.next({
    request: {
      headers: request.headers,
    },
  })

  // set the response headers (set-cookie) from the auth response
  authRes.headers.forEach((value, key) => {
    resWithCombinedHeaders.headers.set(key, value)
  })

  // the headers from the auth middleware should always be returned
  return resWithCombinedHeaders
}
```

## `<Auth0Provider />`

### Passing an initial user from the server

You can wrap your components in an `<Auth0Provider />` and pass an initial user object to make it available to your components using the `useUser()` hook. For example:

```tsx
import { Auth0Provider } from "@auth0/nextjs-auth0"

import { auth0 } from "@/lib/auth0"

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const session = await auth0.getSession()

  return (
    <html lang="en">
      <body>
        <Auth0Provider user={session?.user}>{children}</Auth0Provider>
      </body>
    </html>
  )
}
```

The loaded user will then be used as a fallback in `useUser()` hook.

## Hooks

The SDK exposes hooks to enable you to provide custom logic that would be run at certain lifecycle events.

### `beforeSessionSaved`

The `beforeSessionSaved` hook is run right before the session is persisted. It provides a mechanism to modify the session claims before persisting them.

The hook recieves a `SessionData` object and an ID token. The function must return a Promise that resolves to a `SessionData` object: `(session: SessionData) => Promise<SessionData>`. For example:

```ts
export const auth0 = new Auth0Client({
  async beforeSessionSaved(session, idToken) {
    return {
      ...session,
      user: {
        ...session.user,
        foo: "bar",
      },
    }
  },
})
```

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
      )
    }

    // complete the redirect to the provided returnTo URL
    return NextResponse.redirect(
      new URL(context.returnTo || "/", process.env.APP_BASE_URL)
    )
  },
})
```

## Session configuration

The session configuration can be managed by specifying a `session` object when configuring the Auth0 client, like so:

```ts
export const auth0 = new Auth0Client({
  session: {
    rolling: true,
    absoluteDuration: 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration: 60 * 60 * 24 * 7, // 7 days in seconds
  },
})
```

| Option             | Type      | Description                                                                                                                                                                                                                                   |
| ------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| rolling            | `boolean` | When enabled, the session will continue to be extended as long as it is used within the inactivity duration. Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended. Default: `true`. |
| absoluteDuration   | `number`  | The absolute duration after which the session will expire. The value must be specified in seconds. Default: `3 days`.                                                                                                                         |
| inactivityDuration | `number`  | The duration of inactivity after which the session will expire. The value must be specified in seconds. Default: `1 day`.                                                                                                                     |

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
    async deleteByLogoutToken({ sid, sub }: { sid: string; sub: string }) {
      // optional method to be implemented when using Back-Channel Logout
    },
  },
})
```

## Back-Channel Logout

The SDK can be configured to listen to [Back-Channel Logout](https://auth0.com/docs/authenticate/login/logout/back-channel-logout) events. By default, a route will be mounted `/auth/backchannel-logout` which will verify the logout token and call the `deleteByLogoutToken` method of your session store implementation to allow you to remove the session.

To use Back-Channel Logout, you will need to provide a session store implementation as shown in the [Database sessions](#database-sessions) section above with the `deleteByLogoutToken` implemented.

A `LogoutToken` object will be passed as the parameter to `deleteByLogoutToken` which will contain either a `sid` claim, a `sub` claim, or both.

## Combining middleware

By default, the middleware does not protect any pages. It is used to mount the authentication routes and provide the necessary functionality for rolling sessions.

You can combine multiple middleware, like so:

```ts
export async function middleware(request: NextRequest) {
  const authResponse = await auth0.middleware(request)

  // if path starts with /auth, let the auth middleware handle it
  if (request.nextUrl.pathname.startsWith("/auth")) {
    return authResponse
  }

  // call any other middleware here
  const someOtherResponse = await someOtherMiddleware(request)

  // add any headers from the auth middleware to the response
  for (const [key, value] of authResponse.headers) {
    someOtherResponse.headers.set(key, value)
  }

  return someOtherResponse
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
2. `/auth/logout`: the logout route that must be addedto your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be addedto your Auth0 application's Allowed Callback URLs
4. `/auth/profile`: the route to check the user's session and return their attributes
5. `/auth/access-token`: the route to check the user's session and return an access token (which will be automatically refreshed if a refresh token is available)
6. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

### Custom routes

The default paths can be set using the `routes` configuration option. For example, when instantiating the client:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server"

export const auth0 = new Auth0Client({
  routes: {
    login: "/login",
    logout: "/logout",
    callback: "/callback",
    backChannelLogout: "/backchannel-logout",
  },
})
```

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
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing"

const sessionCookieValue = await generateSessionCookie(
  {
    user: {
      sub: "user_123",
    },
    tokenSet: {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: 123456789,
    },
  },
  {
    secret: process.env.AUTH0_SECRET!,
  }
)
```


## Programmatically starting interactive login

Additionally to the ability to initialize the interactive login process by redirecting the user to the built-in `auth/login` endpoint,
the `startInteractiveLogin` method can also be called programmatically.

```typescript
import { auth0 } from "./lib/auth0";
import { NextRequest } from "next/server";

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
    audience: "urn:custom:api",
  },
});
```

The second option is by configuring `authorizationParams` when calling `startInteractiveLogin`:

```ts
import { auth0 } from "./lib/auth0";
import { NextRequest } from "next/server";

export const GET = async (req: NextRequest) => {
  // Call startInteractiveLogin with optional parameters
  return auth0.startInteractiveLogin({
    authorizationParameters: {
      scope: "openid profile email",
      audience: "urn:custom:api",
    }
  });
};
```

## The `returnTo` parameter

### Redirecting the user after authentication

When calling `startInteractiveLogin`, the `returnTo` parameter can be configured to specify where you would like to redirect the user to after they have completed their authentication and have returned to your application.

```ts
import { auth0 } from "./lib/auth0";
import { NextRequest } from "next/server";

export const GET = async (req: NextRequest) => {
  return auth0.startInteractiveLogin({
    returnTo: '/dashboard',
  });
};
```

> [!NOTE]  
> The URLs specified as `returnTo` parameters must be registered in your client's **Allowed Callback URLs**.
