# Examples

- [Basic Setup](#basic-setup)
- [Customise handlers behaviour](#customise-handlers-behaviour)
- [Use custom auth urls](#use-custom-auth-urls)
- [Protect an API Route](#protect-an-api-route)
- [Protecting a Server Side Rendered (SSR) Page](#protecting-a-server-side-rendered-ssr-page)
- [Protecting a Client Side Rendered (CSR) Page](#protecting-a-client-side-rendered-csr-page)
- [Access an External API from an API Route](#access-an-external-api-from-an-api-route)
- [Access an External API from the front end](#access-an-external-api-from-the-front-end)
- [Create your own instance of the SDK](#create-your-own-instance-of-the-sdk)

All examples can be seen running in the [Kitchen Sink example app](./examples/kitchen-sink-example)

## Basic Setup

Configure the required options in an `.env.local` file in the root of your application:

```dotenv
AUTH0_SECRET=LONG_RANDOM_VALUE
AUTH0_ISSUER_BASE_URL=https://your-tenant.auth0.com
AUTH0_BASE_URL=http://localhost:3000
AUTH0_CLIENT_ID=CLIENT_ID
AUTH0_CLIENT_SECRET=CLIENT_SECRET
```

Create a [Dynamic API Route handler](https://nextjs.org/docs/api-routes/dynamic-api-routes) at `/pages/api/auth/[...auth0].js`

```javascript
import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth();
```

This will create the following urls: `/api/auth/login`, `/api/auth/callback`, `/api/auth/logout` and `/api/auth/me`.

Check the user's authentication state and log them in or out from the front end using the `useUser` hook.

```jsx
// pages/index.jsx
import { useUser } from '@auth0/nextjs-auth0';

export default () => {
  const { user, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;
  
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

## Customise handlers behaviour

Pass custom parameters to the auth handlers or add your own logging and error handling.

```javascript
// /pages/api/auth/[...auth0].js
import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
import { myCustomLogger, myCustomErrorReporter } from '../utils';

export default handleAuth({
  async login(req, res) {
    try {
      // Add your own custom logger
      myCustomLogger('Logging in');
      // Pass custom parameters to login
      await handleLogin(req, res, {
        authorizationParams: {
          custom_param: 'custom'
        },
        returnTo: '/custom-page'
      });
    } catch (error) {
      // Add your own custom error handling
      myCustomErrorReporter(error);
      res.status(error.status || 400).end(error.message);
    }
  }
});
```

## Use custom auth urls

Instead of (or in addition to) creating `/pages/api/auth/[...auth0].js` to handle all requests, you can create them individually at different urls.

Eg for login:

```javascript
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

```javascript
// /components/login-button.js
export default () => <a href="/api/custom-login">Login</a>;
```

> Note: you will need to specify this custom login URL when calling `withPageAuthRequired` both the [front end version](https://auth0.github.io/nextjs-auth0/interfaces/frontend_with_page_auth_required.withpageauthrequiredoptions.html#loginurl) and [server side version](https://auth0.github.io/nextjs-auth0/modules/helpers_with_page_auth_required.html#withpageauthrequiredoptions)

## Protect an API Route

Requests to `/pages/api/protected` without a valid session cookie will fail with `401`.

```javascript
// pages/api/protected.js
import { withApiAuthRequired } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function myApiRoute(req, res) {
  res.json({ protected });
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

## Protecting a Server Side Rendered (SSR) Page

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```javascript
// pages/profile.js
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

export default function Profile({ user }) {
  return <div>Hello {user.name}</div>;
}

// You can optionally pass your own `getServerSideProps` function into
// `withPageAuthRequired` and the props will be merged with the `user` prop
export const getServerSideProps = withPageAuthRequired();
```

See a running example of a [SSR protected page](./examples/kitchen-sink-example/pages/profile-ssr.tsx) in the kitchen-sink example app.

## Protecting a Client Side Rendered (CSR) Page

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```javascript
// pages/profile.js
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

export default withPageAuthRequired(function Profile({ user }) {
  return <div>Hello {user.name}</div>;
});
```

See a running example of a [CSR protected page](./examples/kitchen-sink-example/pages/profile.tsx) in the kitchen-sink example app.

## Access an External API from an API Route

Get an Access Token by specifying `response_type: 'code'` and providing your API's audience and scopes.

```javascript
// /pages/api/auth/[...auth0].js
import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';

export default handleAuth({
  async login(req, res) {
    try {
      await handleLogin(req, res, {
        response_type: 'code',
        audience: 'https://api.example.com/products',
        scope: 'openid profile email read:products'
      });
    } catch (error) {
      res.status(error.status || 400).end(error.message);
    }
  }
});
```

Use the Session to protect your API Route and the Access Token to protect your external API.
The API route serves as a proxy between your front end and the external API.

```javascript
// /pages/api/products.js
import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function products(req, res) {
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

## Access an External API from the front end

In some instances you might want to interact with a protected External API directly from the front end,
for example it might be a Web Socket API that can't be easily proxied through a Next API Route.

> _Note_ the security model of `nextjs-auth0` is that the tokens are witheld from the front end
> using an encrypted `HttpOnly` cookie session. This example bypasses this security model by giving
> the front end direct access to the Access Token, so adds a risk (similar to a SPA) that this could
> be stolen via XSS - and therefore should be avoided if possible. If this is your main data fetching
> model, you may find that a SPA and `auth0-react` is more suitable for your needs. See the Next.js example
> at https://github.com/auth0/auth0-react/blob/master/EXAMPLES.md#3-protecting-a-route-in-a-nextjs-app-in-spa-mode

Create an API route that returns the Access Token as a JSON response.

```javascript
// pages/api/token.js
import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';

export default withApiAuthRequired(async function token(req, res) {
  const { accessToken } = await getAccessToken(req, res, {
    scopes: ['read:products']
  });
  res.status(200).json({ accessToken });
});
```

Fetch the Access Token in the front end and use it to access an External API directly.

```jsx
// pages/products
import useSWR from 'swr';
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

const fetcher = async (uri) => {
  const atResponse = await fetch('/api/token');
  const { accessToken } = await atResponse.json();
  const response = await fetch(uri, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return response.json();
};

export default withPageAuthRequired(function Products() {
  const { data, error } = useSWR('https://api.example.com/products', fetcher);
  if (error) return <div>oops... {error.message}</div>;
  if (data === undefined) return <div>Loading...</div>;
  return (
    <ul>
      {data.map(({ name }) => (
        <li>{name}</li>
      ))}
    </ul>
  );
});
```

## Create your own instance of the SDK

When you use the named exports, the SDK creates an instance of the SDK for you and configures it with the provided environmental variables, eg:

```js
// These named exports create and manage their own instance of the SDK configured with
// the provided AUTH0_* environment variables
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
- You may not want to use environment variables for configuration of secrets (eg using CredStash or AWS's Key Management Service)

In this case you can use the [initAuth0](https://auth0.github.io/nextjs-auth0/modules/instance.html) method to create an instance, eg:

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

Now rather than using the named exports, you can use the instance methods directly, eg:

```js
// pages/api/auth/[...auth0].js
import auth0 from '../../../utils/auth0';

// Use the instance method
export default auth0.handleAuth();
```

> Note: You should not use the instance methods in combination with the named exports,
> otherwise you will be creating multiple instances of the sdk, eg:

```js
// DON'T Mix instance methods and named exports
import auth0 from '../../../utils/auth0';
import { handleLogin } from '@auth0/nextjs-auth0';

export default auth0.handleAuth({
  // <= instance method
  async login(req, res) {
    try {
      // `auth0.handleAuth` and `handleLogin` will be using separate instances.
      // You should use `auth0.handleLogin` instead
      await handleLogin(req, res); // <= named export
    } catch (error) {
      res.status(error.status || 400).end(error.message);
    }
  }
});
```
