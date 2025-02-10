![nextjs-auth0](https://cdn.auth0.com/website/sdks/banners/nextjs-auth0-banner.png)

The Auth0 Next.js SDK is a library for implementing user authentication in Next.js applications.

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Contributing](#contributing)

## Documentation

- [QuickStart](https://auth0.com/docs/quickstart/webapp/nextjs)- our guide for adding Auth0 to your Next.js app.
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

```
AUTH0_DOMAIN=
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=
AUTH0_SECRET=
APP_BASE_URL=
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.

The `AUTH0_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 32
```

The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

> [!IMPORTANT]  
> You will need to register the follwing URLs in your Auth0 Application via the [Auth0 Dashboard](https://manage.auth0.com):
>
> - Add `http://localhost:3000/auth/callback` to the list of **Allowed Callback URLs**
> - Add `http://localhost:3000` to the list of **Allowed Logout URLs**

### 3. Create the Auth0 SDK client

Create an instance of the Auth0 client. This instance will be imported and used in anywhere we need access to the authentication methods on the server.

Add the following contents to a file named `lib/auth0.ts`:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server"

export const auth0 = new Auth0Client()
```

### 4. Add the authentication middleware

Create a `middleware.ts` file in the root of your project's directory:

```ts
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

> [!NOTE]  
> If you're using a `src/` directory, the `middleware.ts` file must be created inside the `src/` directory.

You can now begin to authenticate your users by redirecting them to your application's `/auth/login` route:

```tsx
import { auth0 } from "@/lib/auth0"

export default async function Home() {
  const session = await auth0.getSession()

  if (!session) {
    return (
      <main>
        <a href="/auth/login?screen_hint=signup">Sign up</a>
        <a href="/auth/login">Log in</a>
      </main>
    )
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}!</h1>
    </main>
  )
}
```

> [!IMPORTANT]  
> You must use `<a>` tags instead of the `<Link>` component to ensure that the routing is not done client-side as that may result in some unexpected behavior.

## Customizing the client

You can customize the client by using the options below:

| Option                      | Type                      | Description                                                                                                                                                                                                                            |
| --------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| domain                      | `string`                  | The Auth0 domain for the tenant (e.g.: `example.us.auth0.com` or `https://example.us.auth0.com`). If it's not specified, it will be loaded from the `AUTH0_DOMAIN` environment variable.                                               |
| clientId                    | `string`                  | The Auth0 client ID. If it's not specified, it will be loaded from the `AUTH0_CLIENT_ID` environment variable.                                                                                                                         |
| clientSecret                | `string`                  | The Auth0 client secret. If it's not specified, it will be loaded from the `AUTH0_CLIENT_SECRET` environment variable.                                                                                                                 |
| authorizationParameters     | `AuthorizationParameters` | The authorization parameters to pass to the `/authorize` endpoint. See [Passing authorization parameters](#passing-authorization-parameters) for more details.                                                                         |
| clientAssertionSigningKey   | `string` or `CryptoKey`   | Private key for use with `private_key_jwt` clients. This can also be specified via the `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable.                                                                                      |
| clientAssertionSigningAlg   | `string`                  | The algorithm used to sign the client assertion JWT. This can also be provided via the `AUTH0_CLIENT_ASSERTION_SIGNING_ALG` environment variable.                                                                                      |
| appBaseUrl                  | `string`                  | The URL of your application (e.g.: `http://localhost:3000`). If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.                                                                                    |
| secret                      | `string`                  | A 32-byte, hex-encoded secret used for encrypting cookies. If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.                                                                                      |
| signInReturnToPath          | `string`                  | The path to redirect the user to after successfully authenticating. Defaults to `/`.                                                                                                                                                   |
| session                     | `SessionConfiguration`    | Configure the session timeouts and whether to use rolling sessions or not. See [Session configuration](#session-configuration) for additional details.                                                                                 |
| beforeSessionSaved          | `BeforeSessionSavedHook`  | A method to manipulate the session before persisting it. See [beforeSessionSaved](#beforesessionsaved) for additional details.                                                                                                         |
| onCallback                  | `OnCallbackHook`          | A method to handle errors or manage redirects after attempting to authenticate. See [onCallback](#oncallback) for additional details.                                                                                                  |
| sessionStore                | `SessionStore`            | A custom session store implementation used to persist sessions to a data store. See [Database sessions](#database-sessions) for additional details.                                                                                    |
| pushedAuthorizationRequests | `boolean`                 | Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.                                                                                                            |
| routes                      | `Routes`                  | Configure the paths for the authentication routes. See [Custom routes](#custom-routes) for additional details.                                                                                                                         |
| allowInsecureRequests       | `boolean`                 | Allow insecure requests to be made to the authorization server. This can be useful when testing with a mock OIDC provider that does not support TLS, locally. This option can only be used when `NODE_ENV` is not set to `production`. |
| httpTimeout                 | `number`                  | Integer value for the HTTP timeout in milliseconds for authentication requests. Defaults to `5000` milliseconds                                                                                                                        |
| enableTelemetry             | `boolean`                 | Boolean value to opt-out of sending the library name and version to your authorization server via the `Auth0-Client` header. Defaults to `true`.                                                                                       |

## Routes

The SDK mounts 6 routes:

1. `/auth/login`: the login route that the user will be redirected to to start a initiate an authentication transaction
2. `/auth/logout`: the logout route that must be addedto your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be addedto your Auth0 application's Allowed Callback URLs
4. `/auth/profile`: the route to check the user's session and return their attributes
5. `/auth/access-token`: the route to check the user's session and return an access token (which will be automatically refreshed if a refresh token is available)
6. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

## Cookies and Security

All cookies will be set to `HttpOnly, SameSite=Lax` and will be set to `Secure` if the application's `APP_BASE_URL` is `https`.

The `HttpOnly` setting will make sure that client-side JavaScript is unable to access the cookie to reduce the attack surface of [XSS attacks](https://auth0.com/blog/developers-guide-to-common-vulnerabilities-and-how-to-prevent-them/#Cross-Site-Scripting--XSS-).

The `SameSite=Lax` setting will help mitigate CSRF attacks. Learn more about SameSite by reading the ["Upcoming Browser Behavior Changes: What Developers Need to Know"](https://auth0.com/blog/browser-behavior-changes-what-developers-need-to-know/) blog post.

## Caching and Security

Many hosting providers will offer to cache your content at the edge in order to serve data to your users as fast as possible. For example Vercel will [cache your content on the Vercel Edge Network](https://vercel.com/docs/concepts/edge-network/caching) for all static content and Serverless Functions if you provide the necessary caching headers on your response.

It's generally a bad idea to cache any response that requires authentication, even if the response's content appears safe to cache there may be other data in the response that isn't.

This SDK offers a rolling session by default, which means that any response that reads the session will have a `Set-Cookie` header to update the cookie's expiry. Vercel and potentially other hosting providers include the `Set-Cookie` header in the cached response, so even if you think the response's content can be cached publicly, the responses `Set-Cookie` header cannot.

Check your hosting provider's caching rules, but in general you should **never** cache responses that either require authentication or even touch the session to check authentication (e.g.: `getSession` or `getAccessToken`).

## Error Handling and Security

If you write your own error handler, you should **not** render the error `message`, or `error` and `error_description` properties returned via the OpenID Connect `error` query parameter without using a templating engine that will properly [escape characters](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content) to avoid potential XSS vulenrabilities.

## Comparison with the Auth0 React SDK

We also provide an Auth0 React SDK, [auth0-react](https://github.com/auth0/auth0-react), which may be suitable for your Next.js application.

The SPA security model used by `auth0-react` is different from the Web Application security model used by this SDK. In short, this SDK protects pages and API routes with a cookie session (see ["Cookies and Security"](#cookies-and-security)). A SPA library like `auth0-react` will store the user's ID Token and Access Token directly in the browser and use them to access external APIs directly.

You should be aware of the security implications of both models. However, [auth0-react](https://github.com/auth0/auth0-react) may be more suitable for your needs if you meet any of the following scenarios:

- You are using [Static HTML Export](https://nextjs.org/docs/advanced-features/static-html-export) with Next.js.
- You do not need to access user data during server-side rendering.
- You want to get the access token and call external API's directly from the frontend layer rather than using Next.js API Routes as a proxy to call external APIs

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/express-openid-connect/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/express-openid-connect/blob/master/LICENSE"> LICENSE</a> file for more info.
</p>
