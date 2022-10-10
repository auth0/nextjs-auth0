# Examples

- [Basic Setup](#basic-setup)
- [Customize handlers behavior](#customize-handlers-behavior)
- [Use custom auth urls](#use-custom-auth-urls)
- [Protecting a Server-Side Rendered (SSR) Page](#protecting-a-server-side-rendered-ssr-page)
- [Protecting a Client-Side Rendered (CSR) Page](#protecting-a-client-side-rendered-csr-page)
- [Protect an API Route](#protect-an-api-route)
- [Protecting pages with Middleware](#protecting-pages-with-middleware)
- [Access an External API from an API Route](#access-an-external-api-from-an-api-route)
- [Create your own instance of the SDK](#create-your-own-instance-of-the-sdk)
- [Add a signup handler](#add-a-signup-handler)

All examples can be seen running in the [Kitchen Sink example app](./examples/kitchen-sink-example).

## Basic Setup

Configure the required options in an `.env.local` file in the root of your application:

```sh
AUTH0_SECRET='LONG_RANDOM_VALUE'
AUTH0_BASE_URL='http://localhost:3000'
AUTH0_ISSUER_BASE_URL='https://your-tenant.auth0.com'
AUTH0_CLIENT_ID='CLIENT_ID'
AUTH0_CLIENT_SECRET='CLIENT_SECRET'
```

Create a [dynamic API route handler](https://nextjs.org/docs/api-routes/dynamic-api-routes) at `/pages/api/auth/[...auth0].js`.

```js
import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth();
```

This will create the following urls: `/api/auth/login`, `/api/auth/callback`, `/api/auth/logout` and `/api/auth/me`.

Wrap your `pages/_app.jsx` component in the `UserProvider` component.

```jsx
// pages/_app.jsx
import React from 'react';
import { UserProvider } from '@auth0/nextjs-auth0';

export default function App({ Component, pageProps }) {
  // You can optionally pass the `user` prop from pages that require server-side
  // rendering to prepopulate the `useUser` hook.
  const { user } = pageProps;

  return (
    <UserProvider user={user}>
      <Component {...pageProps} />
    </UserProvider>
  );
}
```

Check the user's authentication state and log them in or out from the front end using the `useUser` hook.

```jsx
// pages/index.jsx
import { useUser } from '@auth0/nextjs-auth0';

export default () => {
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
};
```

Have a look at the `basic-example` app [./examples/basic-example](./examples/basic-example).

## Customize handlers behavior

Pass custom parameters to the auth handlers or add your own logging and error handling.

```js
// pages/api/auth/[...auth0].js
import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
import { myCustomLogger, myCustomErrorReporter } from '../utils';

export default handleAuth({
  async login(req, res) {
    // Add your own custom logger
    myCustomLogger('Logging in');
    // Pass custom parameters to login
    await handleLogin(req, res, {
      authorizationParams: {
        custom_param: 'custom'
      },
      returnTo: '/custom-page'
    });
  },
  invite: loginHandler({
    authorizationParams: (req) => {
      invitation: req.query.invitation;
    }
  }),
  'login-with-google': loginHandler({ authorizationParams: { connection: 'google' } }),
  'refresh-profile': profileHandler({ refetch: true }),
  onError(req, res, error) {
    // Add your own custom error handling
    myCustomErrorReporter(error);
    res.status(error.status || 400).end();
  }
});
```

## Use custom auth urls

Instead of (or in addition to) creating `/pages/api/auth/[...auth0].js` to handle all requests, you can create them individually at different urls.

Eg for login:

```js
// api/custom-login.js
import { handleLogin } from '@auth0/nextjs-auth0';

export default async function login(req, res) {
  try {
    await handleLogin(req, res);
  } catch (error) {
    res.status(error.status || 400).end(error.message);
  }
}
```

```jsx
// components/login-button.js
export default () => <a href="/api/custom-login">Login</a>;
```

> Note: If you customize the login url you will need to set the environment variable `NEXT_PUBLIC_AUTH0_LOGIN` to this custom value for `withPageAuthRequired` to work correctly. And if you customize the profile url, you will need to set the `NEXT_PUBLIC_AUTH0_PROFILE` environment variable to this custom value for the `useUser` hook to work properly.

## Protecting a Server-Side Rendered (SSR) Page

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```jsx
// pages/profile.js
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

export default function Profile({ user }) {
  return <div>Hello {user.name}</div>;
}

// You can optionally pass your own `getServerSideProps` function into
// `withPageAuthRequired` and the props will be merged with the `user` prop
export const getServerSideProps = withPageAuthRequired();
```

See a running example of an [SSR protected page](./examples/kitchen-sink-example/pages/profile-ssr.tsx) in the kitchen-sink example app or refer to the full list of configuration options for `withPageAuthRequired` [here](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequiredoptions).

## Protecting a Client-Side Rendered (CSR) Page

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```jsx
// pages/profile.js
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

export default withPageAuthRequired(function Profile({ user }) {
  return <div>Hello {user.name}</div>;
});
```

See a running example of a [CSR protected page](./examples/kitchen-sink-example/pages/profile.tsx) in the kitchen-sink example app.

## Protect an API Route

Requests to `/pages/api/protected` without a valid session cookie will fail with `401`.

```js
// pages/api/protected.js
import { withApiAuthRequired, getSession } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function myApiRoute(req, res) {
  const { user } = getSession(req, res);
  res.json({ protected: 'My Secret', id: user.sub });
});
```

Then you can access your API from the frontend with a valid session cookie.

```jsx
// pages/products
import useSWR from 'swr';
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

const fetcher = async (uri) => {
  const response = await fetch(uri);
  return response.json();
};

export default withPageAuthRequired(function Products() {
  const { data, error } = useSWR('/api/protected', fetcher);
  if (error) return <div>oops... {error.message}</div>;
  if (data === undefined) return <div>Loading...</div>;
  return <div>{data.protected}</div>;
});
```

See a running example in the kitchen-sink example app, the [protected API route](./examples/kitchen-sink-example/pages/api/shows.ts) and
the [frontend code to access the protected API](./examples/kitchen-sink-example/pages/shows.tsx).

## Protecting pages with Middleware

Protect your pages with Next.js Middleware.

To protect all your routes:

```js
// middleware.js
import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/middleware';

export default withMiddlewareAuthRequired();
```

To protect specific routes:

```js
// middleware.js
import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/middleware';

export default withMiddlewareAuthRequired();

export const config = {
  matcher: '/about/:path*'
};
```

For more info see: https://nextjs.org/docs/advanced-features/middleware#matching-paths

To run custom middleware for authenticated users:

```js
// middleware.js
import { withMiddlewareAuthRequired, getSession } from '@auth0/nextjs-auth0/middleware';

export default withMiddlewareAuthRequired(async function middleware(req) {
  const res = NextResponse.next();
  const user = await getSession(req, res);
  res.cookies.set('hl', user.language);
  return res;
});
```

## Access an External API from an API Route

Get an access token by providing your API's audience and scopes. You can pass them directly to the `handlelogin` method, or use environment variables instead.

```js
// pages/api/auth/[...auth0].js
import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';

export default handleAuth({
  login: handleLogin({
    authorizationParams: {
      audience: 'https://api.example.com/products', // or AUTH0_AUDIENCE
      // Add the `offline_access` scope to also get a Refresh Token
      scope: 'openid profile email read:products' // or AUTH0_SCOPE
    }
  })
});
```

Use the session to protect your API route and the access token to protect your external API.
The API route serves as a proxy between your front end and the external API.

```js
// pages/api/products.js
import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function products(req, res) {
  // If your access token is expired and you have a refresh token
  // `getAccessToken` will fetch you a new one using the `refresh_token` grant
  const { accessToken } = await getAccessToken(req, res, {
    scopes: ['read:products']
  });
  const response = await fetch('https://api.example.com/products', {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const products = await response.json();
  res.status(200).json(products);
});
```

See a running example of the [API route acting as a proxy to an External API](./examples/kitchen-sink-example/pages/api/shows.ts) in the kitchen-sink example app.

### Getting a Refresh Token

- Include the `offline_access` scope your configuration (or `AUTH0_SCOPE`)
- Check "Allow Offline Access" in your [API Settings](https://auth0.com/docs/get-started/apis/api-settings#access-settings)
- Make sure the "Refresh Token" grant is enabled in your [Application Settings](https://auth0.com/docs/get-started/applications/application-settings#grant-types) (this is the default)

## Create your own instance of the SDK

When you use the named exports, the SDK creates an instance of the SDK for you and configures it with the provided environment variables.

```js
// These named exports create and manage their own instance of the SDK configured with
// the provided `AUTH0_*` environment variables
import {
  handleAuth,
  handleLogin,
  handleCallback,
  handleLogout,
  handleProfile,
  withApiAuthRequired,
  withPageAuthRequired,
  getSession,
  getAccessToken
} from '@auth0/nextjs-auth0';
```

However, there are various reasons why you might want to create and manage an instance of the SDK yourself:

- You may want to create your own instance for testing
- You may not want to use environment variables for the configuration of secrets (eg using CredStash or AWS's Key Management Service)

In this case you can use the [initAuth0](https://auth0.github.io/nextjs-auth0/modules/instance.html) method to create an instance.

```js
// utils/auth0.js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  secret: 'LONG_RANDOM_VALUE',
  issuerBaseURL: 'https://your-tenant.auth0.com',
  baseURL: 'http://localhost:3000',
  clientID: 'CLIENT_ID',
  clientSecret: 'CLIENT_SECRET'
});
```

Now rather than using the named exports, you can use the instance methods directly.

```js
// pages/api/auth/[...auth0].js
import auth0 from '../../../utils/auth0';

// Use the instance method
export default auth0.handleAuth();
```

> Note: You should not use the instance methods in combination with the named exports,
> otherwise you will be creating multiple instances of the SDK. For example:

```js
// DON'T Mix instance methods and named exports
import auth0 from '../../../utils/auth0';
import { handleLogin } from '@auth0/nextjs-auth0';

export default auth0.handleAuth({
  // <= instance method
  async login(req, res) {
    try {
      // `auth0.handleAuth` and `handleLogin` will be using separate instances
      // You should use `auth0.handleLogin` instead
      await handleLogin(req, res); // <= named export
    } catch (error) {
      res.status(error.status || 400).end(error.message);
    }
  }
});
```

# Add a signup handler

Pass a custom authorize parameter to the login handler in a custom route.

If you are using the [New Universal Login Experience](https://auth0.com/docs/universal-login/new-experience) you can pass the `screen_hint` parameter.

```js
// pages/api/auth/[...auth0].js
import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';

export default handleAuth({
  signup: handleLogin({ authorizationParams: { screen_hint: 'signup' } })
});
```

Users can then sign up using the signup handler.

```html
<a href="/api/auth/signup">Sign up</a>
```
