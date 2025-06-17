![Auth0 Next.js SDK Banner](https://cdn.auth0.com/website/sdks/banners/nextjs-auth0-banner.png)

The Auth0 Next.js SDK is a library for implementing user authentication in Next.js applications.

![Auth0 Next.js SDK Release](https://img.shields.io/npm/v/@auth0/nextjs-auth0)
![Auth0 Next.js SDK Downloads](https://img.shields.io/npm/dw/@auth0/nextjs-auth0)
[![Auth0 Next.js SDK License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](https://auth0.github.io/nextjs-auth0/) - 💬 [Feedback](#feedback)

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
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client();
```

### 4. Add the authentication middleware

Create a `middleware.ts` file in the root of your project's directory:

```ts
import type { NextRequest } from "next/server";

import { auth0 } from "./lib/auth0"; // Adjust path if your auth0 client is elsewhere

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
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
| appBaseUrl                  | `string`                  | The URL of your application (e.g.: `http://localhost:3000`). If it's not specified, it will be loaded from the `APP_BASE_URL` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| secret                      | `string`                  | A 32-byte, hex-encoded secret used for encrypting cookies. If it's not specified, it will be loaded from the `AUTH0_SECRET` environment variable.                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| signInReturnToPath          | `string`                  | The path to redirect the user to after successfully authenticating. Defaults to `/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| session                     | `SessionConfiguration`    | Configure the session timeouts and whether to use rolling sessions or not. See [Session configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#session-configuration) for additional details. Also allows configuration of cookie attributes like `domain`, `path`, `secure`, `sameSite`, and `transient`. If not specified, these can be configured using `AUTH0_COOKIE_*` environment variables. Note: `httpOnly` is always `true`. See [Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#cookie-configuration) for details. |
| beforeSessionSaved          | `BeforeSessionSavedHook`  | A method to manipulate the session before persisting it. See [beforeSessionSaved](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#beforesessionsaved) for additional details.                                                                                                                                                                                                                                                                                                                                                                                           |
| onCallback                  | `OnCallbackHook`          | A method to handle errors or manage redirects after attempting to authenticate. See [onCallback](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#oncallback) for additional details.                                                                                                                                                                                                                                                                                                                                                                                    |
| sessionStore                | `SessionStore`            | A custom session store implementation used to persist sessions to a data store. See [Database sessions](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#database-sessions) for additional details.                                                                                                                                                                                                                                                                                                                                                                      |
| pushedAuthorizationRequests | `boolean`                 | Configure the SDK to use the Pushed Authorization Requests (PAR) protocol when communicating with the authorization server.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| routes                      | `Routes`                  | Configure the paths for the authentication routes. See [Custom routes](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#custom-routes) for additional details.                                                                                                                                                                                                                                                                                                                                                                                                           |
| allowInsecureRequests       | `boolean`                 | Allow insecure requests to be made to the authorization server. This can be useful when testing with a mock OIDC provider that does not support TLS, locally. This option can only be used when `NODE_ENV` is not set to `production`.                                                                                                                                                                                                                                                                                                                                              |
| httpTimeout                 | `number`                  | Integer value for the HTTP timeout in milliseconds for authentication requests. Defaults to `5000` milliseconds                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| enableTelemetry             | `boolean`                 | Boolean value to opt-out of sending the library name and version to your authorization server via the `Auth0-Client` header. Defaults to `true`.                                                                                                                                                                                                                                                                                                                                                                                                                                    |

## Session Cookie Configuration

You can specify the following environment variables to configure the session cookie:

```env
AUTH0_COOKIE_DOMAIN=
AUTH0_COOKIE_PATH=
AUTH0_COOKIE_TRANSIENT=
AUTH0_COOKIE_SECURE=
AUTH0_COOKIE_SAME_SITE=
```

Respective counterparts are also available in the client configuration. See [Cookie Configuration](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#cookie-configuration) for more details.

## Base Path

Your Next.js application may be configured to use a base path (e.g.: `/dashboard`) — this is usually done by setting the `basePath` option in the `next.config.js` file. To configure the SDK to use the base path, you will also need to set the `NEXT_PUBLIC_BASE_PATH` environment variable which will be used when mounting the authentication routes.

For example, if the `NEXT_PUBLIC_BASE_PATH` environment variable is set to `/dashboard`, the SDK will mount the authentication routes on `/dashboard/auth/login`, `/dashboard/auth/callback`, `/dashboard/auth/profile`, etc.

> [!NOTE]
> We do not recommend using the `NEXT_PUBLIC_BASE_PATH` environment variable in conjunction with a `APP_BASE_URL` that contains a path component. If your application is configured to use a base path, you should set the `APP_BASE_URL` to the root URL of your application (e.g.: `https://example.com`) and use the `NEXT_PUBLIC_BASE_PATH` environment variable to specify the base path (e.g.: `/dashboard`).

## Configuration Validation

The SDK performs validation of required configuration options when initializing the `Auth0Client`. The following options are mandatory and must be provided either through constructor options or environment variables:

- `domain` (or `AUTH0_DOMAIN` environment variable)
- `clientId` (or `AUTH0_CLIENT_ID` environment variable)
- `appBaseUrl` (or `APP_BASE_URL` environment variable)
- `secret` (or `AUTH0_SECRET` environment variable)
- Either:
  - `clientSecret` (or `AUTH0_CLIENT_SECRET` environment variable), OR
  - `clientAssertionSigningKey` (or `AUTH0_CLIENT_ASSERTION_SIGNING_KEY` environment variable)

If any of these required options are missing, the SDK will issue a warning with a detailed message explaining which options are missing and how to provide them.

## Routes

The SDK mounts 6 routes:

1. `/auth/login`: the login route that the user will be redirected to to initiate an authentication transaction
2. `/auth/logout`: the logout route that must be added to your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be added to your Auth0 application's Allowed Callback URLs
4. `/auth/profile`: the route to check the user's session and return their attributes
5. `/auth/access-token`: the route to check the user's session and return an access token (which will be automatically refreshed if a refresh token is available)
6. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

> [!IMPORTANT]  
> The `/auth/access-token` route is enabled by default, but is only neccessary when the access token is needed on the client-side. If this isn't something you need, you can disable this endpoint by setting `enableAccessTokenEndpoint` to `false`.

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
