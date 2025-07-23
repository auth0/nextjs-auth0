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

> [!NOTE]
> In v3 the `audience` parameter could be specified via the `AUTH0_AUDIENCE` environment variable. In v4, the `audience` parameter must be specified as a query parameter or via the `authorizationParamaters` configuration option. For more information on how to pass custom parameters in v4, please see [Passing custom authorization parameters](#passing-custom-authorization-parameters).

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

import { auth0 } from "./lib/auth0" // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request)
}
```

For a complete example, see [the Getting Started section](https://github.com/auth0/nextjs-auth0/tree/main?tab=readme-ov-file#getting-started).

Additionally, in v4, the mounted routes drop the `/api` prefix. For example, the default login route is now `/auth/login` instead of `/api/auth/login`. To link to the login route, it would now be: `<a href="/auth/login">Log in</a>`.

> [!NOTE]  
> If you are using an existing client, you will need to update your **Allowed Callback URLs** accordingly.

The complete list of routes mounted by the SDK can be found [here](https://github.com/auth0/nextjs-auth0/tree/main?tab=readme-ov-file#routes).

## The Auth0 middleware

In v4, the Auth0 middleware is a central component of the SDK. It serves a number of core functions such as registering the required authentication endpoints, providing rolling sessions functionality, keeping access tokens fresh, etc.

When configuring your application to use v4 of the SDK, it is now **required** to mount the middleware:

```ts
// middleware.ts

import type { NextRequest } from "next/server"

import { auth0 } from "./lib/auth0" // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request) // Returns a NextResponse object
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
> [!NOTE]  
> The above middleware is a basic setup. It passes incoming requests to the Auth0 SDK's request handler, which in turn manages the [default auto-mounted authentication routes](https://github.com/auth0/nextjs-auth0/blob/main/README.md#routes), user sessions, and the overall authentication flow. It does **not** protect any routes by default, in order to protect routes from unauthenticated users, read the section below on [protecting routes](https://github.com/auth0/nextjs-auth0/blob/main/V4_MIGRATION_GUIDE.md#protecting-routes).

See [the Getting Started section](https://github.com/auth0/nextjs-auth0/tree/main?tab=readme-ov-file#getting-started) for details on how to configure the middleware.

### Protecting routes

By default, **the middleware does not protect any routes**. To protect a page, you can use the `getSession()` handler in the middleware, like so:

```ts
export async function middleware(request) {
    const authRes = await auth0.middleware(request); // Returns a NextResponse object

    // Ensure your own middleware does not handle the `/auth` routes, auto-mounted and handled by the SDK
    if (request.nextUrl.pathname.startsWith("/auth")) {
      return authRes;
    }

    // Allow access to public routes without requiring a session
    if (request.nextUrl.pathname === ("/")) {
      return authRes;
    }

    // Any route that gets to this point will be considered a protected route, and require the user to be logged-in to be able to access it
    const { origin } = new URL(request.url)
    const session = await auth0.getSession(request)

    // If the user does not have a session, redirect to login
    if (!session) {
      return NextResponse.redirect(`${origin}/auth/login`)
    }

    // If a valid session exists, continue with the response from Auth0 middleware
    // You can also add custom logic here...
    return authRes
}
```

> [!NOTE]  
> We recommend keeping the security checks as close as possible to the data source you're accessing. This is also in-line with [the recommendations from the Next.js team](https://nextjs.org/docs/app/building-your-application/authentication#optimistic-checks-with-middleware-optional).


### Combining with other middleware

For scenarios where you need to combine the Auth0 middleware with other Next.js middleware, please refer to the [Combining middleware](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#combining-middleware) guide for examples and best practices.

## Migrating `<UserProvider />` to `<Auth0Provider />`

The `<UserProvider />` has been renamed to `<Auth0Provider />`.

Previously, when setting up your application to use v3 of the SDK, it was required to wrap your layout in the `<UserProvider />`. **This is no longer required by default.**

If you would like to pass an initial user during server rendering to be available to the `useUser()` hook, you can wrap your components with the new `<Auth0Provider />` ([see example](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#auth0provider-)).

## Rolling sessions

In v4, rolling sessions are enabled by default and are handled automatically by the middleware with no additional configuration required.

See the [session configuration section](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for additional details on how to configure it.

## Migrating from `withPageAuthRequired` and `withApiAuthRequired`

`withPageAuthRequired` and `withApiAuthRequired` have been removed from v4 of the SDK. Instead, we recommend adding a `getSession()` check or relying on `useUser()` hook where you would have previously used the helpers.

On the server-side, the `getSession()` method can be used to check if the user is authenticated:

```tsx
// Example for an App Router Server Component
import { redirect } from 'next/navigation'
import { auth0 } from './lib/auth0' // Adjust path if your auth0 client is elsewhere

export default async function Page() {
  const session = await auth0.getSession()

  if (!session) {
    // The user will be redirected to authenticate and then taken to the
    // /dashboard route after successfully being authenticated.
    return redirect('/auth/login?returnTo=/dashboard')
  }

  return <h1>Hello, {session.user.name}</h1>
}
```

The `getSession()` method can be used in the App Router in Server Components, Server Routes (APIs), Server Actions, and middleware.

In the Pages Router, the `getSession(req)` method takes a request object and can be used in `getServerSideProps`, API routes, and middleware.

Read more about [accessing the authenticated user in various contexts (browser, server, middleware) in the Examples guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#accessing-the-authenticated-user).

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

Read more about [passing authorization parameters](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#passing-authorization-parameters).

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

If you'd like to customize the `user` object to include additional custom claims from the ID token, you can use the `beforeSessionSaved` hook (see [beforeSessionSaved hook](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#beforesessionsaved))
For a list of default claims included in the user object, refer to the [ID Token claims and the user object section in the Examples guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#id-token-claims-and-the-user-object).

## Handling Dynamic Base URLs (e.g. Vercel Preview Deployments)
When deploying to platforms like Vercel with dynamic preview URLs, it's important to set the correct appBaseUrl and redirect_uri at runtime — especially in preview environments where URLs change per deployment.
1. Set `APP_BASE_URL` dynamically in `next.config.js`:
```ts
// next.config.js
module.exports = {
  env: {
    APP_BASE_URL:
      process.env.VERCEL_ENV === "preview"
        ? `https://${process.env.VERCEL_BRANCH_URL}`
        : process.env.APP_BASE_URL,
  },
};
```
2. Use the `APP_BASE_URL` in your Auth0 configuration:
```ts
export const auth0 = new Auth0Client({
  appBaseUrl: process.env.APP_BASE_URL,
  authorizationParameters: {
    redirect_uri: `${process.env.APP_BASE_URL}/auth/callback`,
    audience: "YOUR_API_AUDIENCE_HERE", // optional
  },
});
```
3. Ensure your Auth0 application settings include the dynamic URL in the **Allowed Callback URLs** and **Allowed Logout URLs** fields. For example, `https://*.vercel.app/auth/callback`.

## Additional changes

- By default, v4 is edge-compatible and as such there is no longer a `@auth0/nextjs-auth0/edge` export.
- All cookies set by the SDK default to `SameSite=Lax`. For details on how to customize cookie attributes, see the [Cookie Configuration section in the Examples guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#cookie-configuration).
- `touchSession` method was removed. The middleware enables rolling sessions by default and can be configured via the [Session configuration section in the Examples guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration).
- `getAccessToken` can now be called in React Server Components. For examples on how to use `getAccessToken` in various environments (browser, App Router, Pages Router, Middleware), refer to the [Getting an access token section in the Examples guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#getting-an-access-token).
- By default, v4 will use [OpenID Connect's RP-Initiated Logout](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0) if it's enabled on the tenant. Otherwise, it will fallback to the `/v2/logout` endpoint.

## Customizing Auth Handlers

In v3, you could customize individual auth handlers by providing custom implementations to the `handleAuth` function:

```ts
// v3 approach (no longer available in v4)
export const GET = handleAuth({
  async logout(req: NextApiRequest, res: NextApiResponse) {
    // Custom logout logic
    console.log('User is logging out');
    
    return await handleLogout(req, res);
  },
  async login(req: NextApiRequest, res: NextApiResponse) {
    // Custom login logic
    return await handleLogin(req, res, {
      authorizationParams: {
        audience: 'https://my-api.com'
      }
    });
  }
});
```

In v4, the auth routes are handled automatically by the middleware, but you can achieve similar customization through two main approaches:

### 1. Run custom code before auth handlers (Middleware Interception)

You can intercept auth routes in your middleware to run custom logic before the auth handlers execute:

```ts
import type { NextRequest } from 'next/server';
import { auth0 } from './lib/auth0';

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);
  
  // Intercept specific auth routes
  if (request.nextUrl.pathname === '/auth/logout') {
    // Custom logout logic runs BEFORE the actual logout
    console.log('User is logging out');
    
    // Example: Set custom cookies
    authRes.cookies.set('logoutTime', new Date().toISOString());
  }
  
  if (request.nextUrl.pathname === '/auth/login') {
    // Custom login logic runs BEFORE the actual login
    console.log('User is attempting to login');
  }
  
  return authRes;
}
```

### 2. Run code after authentication (Callback Hook)

Use the `onCallback` hook to add custom logic after authentication completes:

```ts
import { NextResponse } from 'next/server';
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  async onCallback(error, context, session) {
    if (error) {
      console.error('Authentication error:', error);
      return NextResponse.redirect(
        new URL('/error', process.env.APP_BASE_URL)
      );
    }

    // Custom logic after successful authentication
    if (session) {
      console.log(`User ${session.user.sub} logged in successfully`);
    }

    return NextResponse.redirect(
      new URL(context.returnTo || "/", process.env.APP_BASE_URL)
    );
  }
});
```

### Additional Customization Options

- **Login parameters**: Use query parameters (`/auth/login?audience=...`) or static configuration
- **Session data**: Use the `beforeSessionSaved` hook to modify session data
- **Logout redirects**: Use query parameters (`/auth/logout?returnTo=...`)

> [!IMPORTANT]
> Always validate redirect URLs to prevent open redirect attacks. Use relative URLs when possible.

For detailed examples and implementation patterns, see [Customizing Auth Handlers](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#customizing-auth-handlers) in the Examples guide.
