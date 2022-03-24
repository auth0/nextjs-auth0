# @auth0/nextjs-auth0

The Auth0 Next.js SDK is a library for implementing user authentication in Next.js applications.

[![CircleCI](https://img.shields.io/circleci/build/github/auth0/nextjs-auth0/main?style=flat-square)](https://circleci.com/gh/auth0/nextjs-auth0/tree/main)
[![NPM version](https://img.shields.io/npm/v/@auth0/nextjs-auth0.svg?style=flat-square)](https://npmjs.org/package/@auth0/nextjs-auth0)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
  - [Auth0 Configuration](#auth0-configuration)
  - [Basic Setup](#basic-setup)
- [Documentation](#documentation)
  - [QuickStart](https://auth0.com/docs/quickstart/webapp/nextjs)
  - [API Reference](#api-reference)
  - [v1 Migration Guide](./V1_MIGRATION_GUIDE.md)
  - [Cookies and Security](#cookies-and-security)
  - [Caching and Security](#caching-and-security)
  - [Error Handling and Security](#error-handling-and-security)
  - [Base Path and Internationalized Routing](#base-path-and-internationalized-routing)
  - [Architecture](./ARCHITECTURE.md)
  - [Comparison with auth0-react](#comparison-with-the-auth0-react-sdk)
  - [Testing](#testing)
  - [Deploying](#deploying)
- [Contributing](#contributing)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0?](#what-is-auth0)
- [License](#license)

## Installation

Using [npm](https://npmjs.org):

```sh
npm install @auth0/nextjs-auth0
```

This library supports the following tooling versions:

- Node.js: `^10.13.0 || >=12.0.0`

- Next.js: `>=10`

## Getting Started

### Auth0 Configuration

Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com/#/applications).

> **If you're using an existing application**, verify that you have configured the following settings in your Regular Web Application:
>
> - Click on the "Settings" tab of your application's page.
> - Scroll down and click on the "Show Advanced Settings" link.
> - Under "Advanced Settings", click on the "OAuth" tab.
> - Ensure that "JsonWebToken Signature Algorithm" is set to `RS256` and that "OIDC Conformant" is enabled.

Next, configure the following URLs for your application under the "Application URIs" section of the "Settings" page:

- **Allowed Callback URLs**: `http://localhost:3000/api/auth/callback`
- **Allowed Logout URLs**: `http://localhost:3000/`

Take note of the **Client ID**, **Client Secret**, and **Domain** values under the "Basic Information" section. You'll need these values in the next step.

### Basic Setup

#### Configure the Application

You need to allow your Next.js application to communicate properly with Auth0. You can do so by creating a `.env.local` file under your root project directory that defines the necessary Auth0 configuration values as follows:

```bash
# A long, secret value used to encrypt the session cookie
AUTH0_SECRET='LONG_RANDOM_VALUE'
# The base url of your application
AUTH0_BASE_URL='http://localhost:3000'
# The url of your Auth0 tenant domain
AUTH0_ISSUER_BASE_URL='https://YOUR_AUTH0_DOMAIN.auth0.com'
# Your Auth0 application's Client ID
AUTH0_CLIENT_ID='YOUR_AUTH0_CLIENT_ID'
# Your Auth0 application's Client Secret
AUTH0_CLIENT_SECRET='YOUR_AUTH0_CLIENT_SECRET'
```

You can execute the following command to generate a suitable string for the `AUTH0_SECRET` value:

```bash
node -e "console.log(crypto.randomBytes(32).toString('hex'))"
```

You can see a full list of Auth0 configuration options in the ["Configuration properties"](https://auth0.github.io/nextjs-auth0/modules/config.html#configuration-properties) section of the "Module config" document.

> For more details about loading environmental variables in Next.js, visit the ["Environment Variables"](https://nextjs.org/docs/basic-features/environment-variables) document.

#### Add the Dynamic API Route

Go to your Next.js application and create a [catch-all, dynamic API route handler](https://nextjs.org/docs/api-routes/dynamic-api-routes#optional-catch-all-api-routes) under the `/pages/api` directory:

- Create an `auth` directory under the `/pages/api/` directory.

- Create a `[...auth0].js` file under the newly created `auth` directory.

The path to your dynamic API route file would be `/pages/api/auth/[...auth0].js`. Populate that file as follows:

```js
import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth();
```

Executing `handleAuth()` creates the following route handlers under the hood that perform different parts of the authentication flow:

- `/api/auth/login`: Your Next.js application redirects users to your Identity Provider for them to log in (you can optionally pass a `returnTo` parameter to return to a custom relative URL after login, eg `/api/auth/login?returnTo=/profile`).

- `/api/auth/callback`: Your Identity Provider redirects users to this route after they successfully log in.

- `/api/auth/logout`: Your Next.js application logs out the user.

- `/api/auth/me`: You can fetch user profile information in JSON format.

#### Add the UserProvider to Custom App

Wrap your `pages/_app.js` component with the `UserProvider` component:

```jsx
// pages/_app.js
import React from 'react';
import { UserProvider } from '@auth0/nextjs-auth0';

export default function App({ Component, pageProps }) {
  return (
    <UserProvider>
      <Component {...pageProps} />
    </UserProvider>
  );
}
```

#### Consume Authentication

You can now determine if a user is authenticated by checking that the `user` object returned by the `useUser()` hook is defined. You can also log in or log out your users from the frontend layer of your Next.js application by redirecting them to the appropriate automatically-generated route:

```jsx
// pages/index.js
import { useUser } from '@auth0/nextjs-auth0';

export default function Index() {
  const { user, error, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>{error.message}</div>;

  if (user) {
    return (
      <div>
        Welcome {user.name}! <a href="/api/auth/logout">Logout</a>
      </div>
    );
  }

  return <a href="/api/auth/login">Login</a>;
}
```

> Next linting rules might suggest using the `Link` component instead of an anchor tag. The `Link` component is meant to perform [client-side transitions between pages](https://nextjs.org/docs/api-reference/next/link). As the links point to an API route and not to a page, you should keep them as anchor tags.

There are two additional ways to check for an authenticated user; one for Next.js pages using [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequired) and one for Next.js API routes using [withAPIAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_api_auth_required.html#withapiauthrequired).

For other comprehensive examples, see the [EXAMPLES.md](./EXAMPLES.md) document.

## Documentation

### API Reference

- [Configuration Options](https://auth0.github.io/nextjs-auth0/modules/config.html)

**Server-side methods**:

- [handleAuth](https://auth0.github.io/nextjs-auth0/modules/handlers_auth.html)
- [handleLogin](https://auth0.github.io/nextjs-auth0/modules/handlers_login.html#handlelogin)
- [handleCallback](https://auth0.github.io/nextjs-auth0/modules/handlers_callback.html)
- [handleLogout](https://auth0.github.io/nextjs-auth0/modules/handlers_logout.html)
- [handleProfile](https://auth0.github.io/nextjs-auth0/modules/handlers_profile.html)
- [withApiAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_api_auth_required.html)
- [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequired)
- [getSession](https://auth0.github.io/nextjs-auth0/modules/session_get_session.html)
- [getAccessToken](https://auth0.github.io/nextjs-auth0/modules/session_get_access_token.html)
- [initAuth0](https://auth0.github.io/nextjs-auth0/modules/instance.html)

**Client-side methods/components**:

- [UserProvider](https://auth0.github.io/nextjs-auth0/modules/frontend_use_user.html#userprovider)
- [useUser](https://auth0.github.io/nextjs-auth0/modules/frontend_use_user.html)
- [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/frontend_with_page_auth_required.html)

Visit the auto-generated [API Docs](https://auth0.github.io/nextjs-auth0/) for more details.

### Cookies and Security

All cookies will be set to `HttpOnly, SameSite=Lax` and will be set to `Secure` if the application's `AUTH0_BASE_URL` is `https`.

The `HttpOnly` setting will make sure that client-side JavaScript is unable to access the cookie to reduce the attack surface of [XSS attacks](https://auth0.com/blog/developers-guide-to-common-vulnerabilities-and-how-to-prevent-them/#Cross-Site-Scripting--XSS-).

The `SameSite=Lax` setting will help mitigate CSRF attacks. Learn more about SameSite by reading the ["Upcoming Browser Behavior Changes: What Developers Need to Know"](https://auth0.com/blog/browser-behavior-changes-what-developers-need-to-know/) blog post.

### Caching and Security

Many hosting providers will offer to cache your content at the edge in order to serve data to your users as fast as possible. For example Vercel will [cache your content on the Vercel Edge Network](https://vercel.com/docs/concepts/edge-network/caching) for all static content and Serverless Functions if you provide the necessary caching headers on your response.

It's generally a bad idea to cache any response that requires authentication, even if the response's content appears safe to cache there may be other data in the response that isn't.

This SDK offers a rolling session by default, which means that any response that reads the session will have a `Set-Cookie` header to update the cookie's expiry. Vercel and potentially other hosting providers include the `Set-Cookie` header in the cached response, so even if you think the response's content can be cached publicly, the responses `Set-Cookie` header cannot.

Check your hosting provider's caching rules, but in general you should **never** cache responses that either require authentication or even touch the session to check authentication (eg when using `withApiAuthRequired`, `withPageAuthRequired` or even just `getSession` or `getAccessToken`).

### Error Handling and Security

The default server side error handler for the `/api/auth/*` routes prints the error message to screen, eg

```js
try {
  await handler(req, res);
} catch (error) {
  res.status(error.status || 400).end(error.message);
}
```

Because the error can come from the OpenID Connect `error` query parameter we do some [basic escaping](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content) which makes sure the default error handler is safe from XSS.

If you write your own error handler, you should **not** render the error `message`, or `error` and `error_description` properties without using a templating engine that will properly escape it for other HTML contexts first.

### Base Path and Internationalized Routing

With Next.js you can deploy a Next.js application under a sub-path of a domain using [Base Path](https://nextjs.org/docs/api-reference/next.config.js/basepath) and serve internationalized (i18n) routes using [Internationalized Routing](https://nextjs.org/docs/advanced-features/i18n-routing).

If you use these features the urls of your application will change and so the urls to the nextjs-auth0 routes will change. To accommodate this there are various places in the SDK that you can customise the url.

For example if `basePath: '/foo'` you should prepend this to the `loginUrl` and `profileUrl` specified in your `Auth0Provider`

```jsx
// _app.jsx
function App({ Component, pageProps }) {
  return (
    <UserProvider loginUrl="/foo/api/auth/login" profileUrl="/foo/api/auth/me">
      <Component {...pageProps} />
    </UserProvider>
  );
}
```

Also, any links to login or logout should include the `basePath`:

```html
<a href="/foo/api/auth/login">Login</a><br />
<a href="/foo/api/auth/logout">Logout</a>
```

You should configure [baseUrl](https://auth0.github.io/nextjs-auth0/interfaces/config.baseconfig.html#baseurl) (or the `AUTH0_BASE_URL` environment variable) eg

```shell
# .env.local
AUTH0_BASE_URL=http://localhost:3000/foo
```

For any pages that are protected with the Server Side [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequired) you should update the `returnTo` parameter depending on the `basePath` and `locale` if necessary.

```js
// ./pages/my-ssr-page.jsx
export default MySsrPage = () => <></>;

const getFullReturnTo = (ctx) => {
  // TODO: implement getFullReturnTo based on the ctx.resolvedUrl, ctx.locale
  // and your next.config.js's basePath and i18n settings.
  return '/foo/en-US/my-ssr-page';
};

export const getServerSideProps = (ctx) => {
  const returnTo = getFullReturnTo(ctx.req);
  return withPageAuthRequired({ returnTo })(ctx);
};
```

### Comparison with the Auth0 React SDK

We also provide an Auth0 React SDK, [auth0-react](https://github.com/auth0/auth0-react), which may be suitable for your Next.js application.

The SPA security model used by `auth0-react` is different from the Web Application security model used by this SDK. In short, this SDK protects pages and API routes with a cookie session (see ["Cookies and Security"](#cookies-and-security)). A SPA library like `auth0-react` will store the user's ID Token and Access Token directly in the browser and use them to access external APIs directly.

You should be aware of the security implications of both models. However, [auth0-react](https://github.com/auth0/auth0-react) may be more suitable for your needs if you meet any of the following scenarios:

- You are using [Static HTML Export](https://nextjs.org/docs/advanced-features/static-html-export) with Next.js.
- You do not need to access user data during server-side rendering.
- You want to get the access token and call external API's directly from the frontend layer rather than using Next.js API Routes as a proxy to call external APIs

### Testing

By default, the SDK creates and manages a singleton instance to run for the lifetime of the application. When testing your application, you may need to reset this instance, so its state does not leak between tests.

If you're using Jest, we recommend using `jest.resetModules()` after each test. Alternatively, you can look at [creating your own instance of the SDK](./EXAMPLES.md#create-your-own-instance-of-the-sdk), so it can be recreated between tests.

For end to end tests, have a look at how we use a [mock OIDC Provider](./scripts/oidc-provider.js).

# Deploying

For deploying, have a look at [how we deploy our example app to Vercel](./examples/README.md).

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](./CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](./CODE-OF-CONDUCT.md)

Start by installing the dependencies of this project:

```sh
npm install
```

In order to build a release, you can run the following commands, and the output will be stored in the `dist` folder:

```sh
npm run clean
npm run lint
npm run build
```

Additionally, you can also run tests:

```sh
npm run build:test # Build the Next.js test app
npm run test
npm run test:watch
```

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to easily:

- Implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc.), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- Log in users with username/password databases, passwordless, or multi-factor authentication
- Link multiple user accounts together
- Generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- Access demographics and analytics detailing how, when, and where users are logging in
- Enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0) Because you should save time, be happy, and focus on what really matters: building your product.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
