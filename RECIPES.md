# Next.js Auth0 Recipes

Recipes for various authentication scenarios with Auth0 and Next.js

- [nextjs-auth0 (Session auth)](#nextjs-auth0--session-auth-)
  - [Protect an API Route](#protect-an-api-route)
  - [Protecting a Server Side Rendered (SSR) Page](#protecting-a-server-side-rendered--ssr--page)
  - [Protecting a Client Side Rendered (CSR) Page](#protecting-a-client-side-rendered--csr--page)
  - [Access an External API from an API Route](#access-an-external-api-from-an-api-route)
  - [Access an External API from the front end](#access-an-external-api-from-the-front-end)
- [auth0-react (Access Token auth)](#auth0-react--access-token-auth-)
  - [Protecting a Client Side Rendered (CSR) Page](#protecting-a-client-side-rendered--csr--page-1)
  - [Access an API Route](#access-a-nextjs-api-route)
  - [Access an External API from the front end](#access-an-external-api-from-the-front-end-1)

## nextjs-auth0 (Session auth)

Uses a session to protect resources, the session is stored in an encrypted `HttpOnly` cookie to mitigate XSS attacks.

**TODO** Architecture document

### Protect an API Route

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

### Protecting a Server Side Rendered (SSR) Page

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

### Protecting a Client Side Rendered (CSR) Page

Requests to `/pages/profile` without a valid session cookie will be redirected to the login page.

```javascript
// pages/profile.js
import { withPageAuthRequired } from '@auth0/nextjs-auth0';

export default withPageAuthRequired(function Profile({ user }) {
  return <div>Hello {user.name}</div>;
});
```

### Access an External API from an API Route

Get an Access Token by specifying `response_type: 'code'` and providing your API's audience and scopes

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

### Access an External API from the front end

In some instances you might to interact with a protected External API directly from the front end,
for example it might be a Web Socket API that can't be easily proxied through a Next API Route.

_Note_ the security model of `nextjs-auth0` is that the tokens are witheld from the front end
using an encrypted `HttpOnly` cookie session. This example bypasses this security model by giving
the front end direct access to the Access Token, so adds a risk (similar to a SPA) that this could
be stolen via XSS - and therefore should be avoided if possible. If this is your main data fetching
model, you may find that a SPA and `auth0-react` is more suitable for your needs.

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

## auth0-react (Access Token auth)

Uses an Access Token to protect resources, the Access Token is stored on the front end.

**TODO** Architecture document

### Protecting a Client Side Rendered (CSR) Page

Wrap the root element in your `Auth0Provider` to configure the SDK and setup the context for the `useAuth0` hook.

The `onRedirectCallback` will use `next`'s `Router.replace` function to return the user to the protected route after the login:

```jsx
// pages/_app.js
import React from 'react';
import App from 'next/app';
import Router from 'next/router';
import { Auth0Provider } from '@auth0/auth0-react';

const onRedirectCallback = (appState) => {
  // Use Next.js's Router.replace method to replace the url
  Router.replace(appState?.returnTo || '/');
};

class MyApp extends App {
  render() {
    const { Component, pageProps } = this.props;
    return (
      <Auth0Provider
        domain="YOUR_AUTH0_DOMAIN"
        clientId="YOUR_AUTH0_CLIENT_ID"
        redirectUri={typeof window !== 'undefined' && window.location.origin}
        onRedirectCallback={onRedirectCallback}
      >
        <Component {...pageProps} />
      </Auth0Provider>
    );
  }
}

export default MyApp;
```

Create a page that you want to be protected, e.g. a profile page, and wrap it in the `withAuthenticationRequired` HOC:

```jsx
// pages/profile.js
import React from 'react';
import { useAuth0, withAuthenticationRequired } from '@auth0/auth0-react';

const Profile = () => {
  const { user } = useAuth0();
  return (
    <ul>
      <li>Name: {user.nickname}</li>
      <li>E-mail: {user.email}</li>
    </ul>
  );
};

// Wrap the component in the withAuthenticationRequired handler
export default withAuthenticationRequired(Profile);
```

See [Next.js auth0-react example app](https://github.com/auth0/auth0-react/tree/master/examples/nextjs-app)

### Access a Next.js API Route

Protect the API Route with Access Token authorization.

```javascript
// pages/api/products.js
const { NextJwtVerifier, removeNamespaces, claimToArray } = require('@serverless-jwt/next');

const verifyJwt = NextJwtVerifier({
  issuer: 'https://my-tenant.auth0.com/',
  audience: 'https://example.com/api'
});

const requireScope = (scope, apiRoute) =>
  verifyJwt(async (req, res) => {
    const { claims } = req.identityContext;
    if (!claims || !claims.scope || claims.scope.indexOf(scope) === -1) {
      return res.status(403).json({
        error: 'access_denied',
        error_description: `Token does not contain the required '${scope}' scope`
      });
    }
    return apiRoute(req, res);
  });

const apiRoute = async (req, res) => {
  const products = [{ name: 'shoes' }, { name: 'tshirts' }];
  res.json(products);
};

export default requireScope('read:products', apiRoute);
```

Get an Access Token for the API Route and call it directly.

```javascript
import React, { useEffect, useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';

export default withPageAuthRequired(function Products() {
  const { getAccessTokenSilently } = useAuth0();
  const { data, error } = useSWR('/api/products', async (url) => {
    const accessToken = await getAccessTokenSilently({ scope: 'read:products', audience: 'https://example.com/api' });
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    return response.json();
  });
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

### Access an External API from the front end

Get an Access Token for the External API and call it directly.

```javascript
import React, { useEffect, useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';

export default withPageAuthRequired(function Products() {
  const { getAccessTokenSilently } = useAuth0();
  const { data, error } = useSWR('https://api.example.com/products', async (url) => {
    const accessToken = await getAccessTokenSilently({ scope: 'read:products', audience: 'https://api.example.com/' });
    const response = await fetch(uri, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    return response.json();
  });

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
