![nextjs-auth0](https://cdn.auth0.com/website/sdks/banners/nextjs-auth0-banner.png)

The Auth0 Next.js SDK is a library for implementing user authentication in Next.js applications.

![Release](https://img.shields.io/npm/v/@auth0/nextjs-auth0)
[![Coverage](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=jest.coverageThreshold.global.lines&suffix=%25&url=https%3A%2F%2Fraw.githubusercontent.com%2Fauth0%2Fnextjs-auth0%2Fmain%2Fpackage.json)](https://github.com/auth0/nextjs-auth0/blob/main/package.json#L147)
![Downloads](https://img.shields.io/npm/dw/@auth0/nextjs-auth0)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
![CircleCI](https://img.shields.io/circleci/build/github/auth0/nextjs-auth0)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started)- 💻 [API Reference](#api-reference) - 💬 [Feedback](#feedback)

## Documentation

- [QuickStart](https://auth0.com/docs/quickstart/webapp/nextjs)- our guide for adding Auth0 to your Next.js app.
- [FAQs](https://github.com/auth0/nextjs-auth0/blob/main/FAQ.md) - Frequently asked questions about nextjs-auth0.
- [Examples](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md) - lots of examples for your different use cases.
- [Security](https://github.com/auth0/nextjs-auth0/blob/main/SECURITY.md) - Some important security notices that you should check.
- [Architecture](https://github.com/auth0/nextjs-auth0/blob/main/ARCHITECTURE.md) - Architectural overview of the SDK.
- [Testing](https://github.com/auth0/nextjs-auth0/blob/main/TESTING.md) - Some help with testing your nextjs-auth0 application.
- [Deploying](https://github.com/auth0/nextjs-auth0/blob/main/examples/README.md) - How we deploy our example app to Vercel.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### Installation

Using [npm](https://npmjs.org):

```sh
npm install @auth0/nextjs-auth0
```

This library supports the following tooling versions:

- Node.js: `^10.13.0 || >=12.0.0`
- Next.js: `>=10`

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

For other comprehensive examples, see the [EXAMPLES.md](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md) document.

## API Reference

- [Configuration Options](https://auth0.github.io/nextjs-auth0/modules/config.html)

**Server-side methods**:

- [handleAuth](https://auth0.github.io/nextjs-auth0/modules/handlers_auth.html)
- [handleLogin](https://auth0.github.io/nextjs-auth0/modules/handlers_login.html#handlelogin)
- [handleCallback](https://auth0.github.io/nextjs-auth0/modules/handlers_callback.html)
- [handleLogout](https://auth0.github.io/nextjs-auth0/modules/handlers_logout.html)
- [handleProfile](https://auth0.github.io/nextjs-auth0/modules/handlers_profile.html)
- [withApiAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_api_auth_required.html)
- [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequired)
- [getServerSidePropsWrapper](https://auth0.github.io/nextjs-auth0/modules/helpers_get_server_side_props_wrapper.html)
- [getSession](https://auth0.github.io/nextjs-auth0/modules/session_get_session.html)
- [getAccessToken](https://auth0.github.io/nextjs-auth0/modules/session_get_access_token.html)
- [initAuth0](https://auth0.github.io/nextjs-auth0/modules/instance.html)

**Client-side methods/components**:

- [UserProvider](https://auth0.github.io/nextjs-auth0/modules/frontend_use_user.html#userprovider)
- [useUser](https://auth0.github.io/nextjs-auth0/modules/frontend_use_user.html)
- [withPageAuthRequired](https://auth0.github.io/nextjs-auth0/modules/frontend_with_page_auth_required.html)

Visit the auto-generated [API Docs](https://auth0.github.io/nextjs-auth0/) for more details.

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/express-openid-connect/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/express-openid-connect/blob/master/CONTRIBUTING.md)

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
