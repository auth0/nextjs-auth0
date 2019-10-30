# @auth0/nextjs-auth0

Auth0 SDK for signing in to your Next.js applications.

> Note: This library is currently in an experimental state and support is best effort.

[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Support + Feedback](#support--feedback)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Installation

Using [npm](https://npmjs.org):

```sh
npm install @auth0/nextjs-auth0
```

Using [yarn](https://yarnpkg.com):

```sh
yarn add @auth0/nextjs-auth0
```

> Note that this package supports the following versions of Node.js: `^10.13.0 || >=12.0.0`

## Getting Started

### Auth0 Configuration

Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com/). If you're using an existing application you'll want to verify that the following settings are configured as follows:

 - **Json Web Token Signature Algorithm**: `RS256`
 - **OIDC Conformant**: `True`

Go ahead and configure the URLs for your application:

- **Allowed Callback URLs**: http://localhost:3000/api/callback
- **Allowed Logout URLs**: http://localhost:3000/

Take note of the **Client ID**, **Client Secret** and **Domain** of your application because you'll need it in the next step.

### Runtime Configuration

And then create an instance of the Auth0 plugin (eg: under `/utils/auth0.js`):

```js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  scope: 'openid profile',
  redirectUri: 'http://localhost:3000/api/callback',
  postLogoutRedirectUri: 'http://localhost:3000/',
  session: {
    // The secret used to encrypt the cookie.
    cookieSecret: '<RANDOMLY_GENERATED_SECRET>',
    // The cookie lifetime (expiration) in seconds. Set to 8 hours by default.
    cookieLifetime: 60 * 60 * 8,
    // Store the id_token in the session. Defaults to false.
    storeIdToken: false,
    // Store the access_token in the session. Defaults to false.
    storeAccessToken: false,
    // Store the refresh_token in the session. Defaults to false.
    storeRefreshToken: false
  },
  oidcClient: {
    // Optionally configure the timeout in milliseconds for HTTP requests to Auth0.
    httpTimeout: 2500,
    // Optionally configure the clock tolerance in milliseconds, if the time on your server is running behind.
    clockTolerance: 10000
  }
});
```

> Note that when you have configured a Custom Domain in your Auth0 account you should be using that domain (eg: `login.acme.com` instead of `acme.auth0.com`) as the AUTH0_DOMAIN. [You might also need to make changes to your Login page](https://auth0.com/docs/custom-domains/additional-configuration).

### Login

In order to sign in the user we'll first need a link to the login route.

```html
<a href='/api/login'>Login</a>
```

Create an [API Route](https://nextjs.org/docs#api-routes) for this route (`/pages/api/login.js`) which uses the client:

```js
import auth0 from '../../utils/auth0';

export default async function login(req, res) {
  try {
    await auth0.handleLogin(req, res);
  } catch(error) {
    console.error(error)
    res.status(error.status || 400).end(error.message)
  }
}
```

This will redirect the user to Auth0. After the transaction is completed Auth0 will redirect the user back to your application. This is why the callback route (`/pages/api/callback.js`) needs to be created which will create a session cookie:

```js
import auth0 from '../../utils/auth0';

export default async function callback(req, res) {
  try {
    await auth0.handleCallback(req, res, { redirectTo: '/' });
  } catch(error) {
    console.error(error)
    res.status(error.status || 400).end(error.message)
  }
}
```

You can optionally send extra parameters to Auth0 to influence the transaction, for example:

- Showing the login page
- Filling in the user's email address
- Exposing information to the custom login page (eg: to show the signup tab)

```js
import auth0 from '../../utils/auth0';

export default async function login(req, res) {
  try {
    await auth0.handleLogin(req, res, {
      authParams: {
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope',
        foo: 'bar'
      }
    });
  } catch(error) {
    console.error(error)
    res.status(error.status || 400).end(error.message)
  }
}
```

### Logout

For signing the user out we'll also need a logout link:

```html
<a href='/api/logout'>Logout</a>
```

Create an [API Route](https://nextjs.org/docs#api-routes) for this route (`/pages/api/logout.js`) which uses the client:

```js
import auth0 from '../../utils/auth0';

export default async function logout(req, res) {
  try {
    await auth0.handleLogout(req, res);
  } catch(error) {
    console.error(error)
    res.status(error.status || 400).end(error.message)
  }
}
```

### User Profile

If you want to expose a route which returns the user profile to the client you can create an additional route (eg: `/pages/api/me.js`):

```js
import auth0 from '../../utils/auth0';

export default async function me(req, res) {
  try {
    await auth0.handleProfile(req, res);
  } catch(error) {
    console.error(error)
    res.status(error.status || 500).end(error.message)
  }
}
```

You can then load the user after the page has been rendered on the server:

```js
async componentDidMount() {
  const res = await fetch('/api/me');
  if (res.ok) {
    this.setState({
      session: await res.json()
    })
  }
}
```

If you need to access the user's session from within an API route or a Server-rendered page you can use `getSession`. Note that this object will also contain the user's `access_token` and `id_token`.

```js
Profile.getInitialProps = async ({ req, res }) => {
  if (typeof window === 'undefined') {
    const { user } = await auth0.getSession(req);
    if (!user) {
      res.writeHead(302, {
        Location: '/api/login'
      });
      res.end();
      return;
    }

    return { user }
  }
}
```

### Calling an API

It's a common pattern to use Next.js API Routes and proxy them to external APIs. When doing so these APIs typically require an `access_token` to be provided. These APIs can then be configured in Auth0.

In order to get an access_token for an API you'll need to configure the `audience` on the Auth0 plugin and configure it to store the `access_token` in the cookie:

```js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  domain: '<AUTH0_DOMAIN>'
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  audience: 'https://api.mycompany.com/',
  scope: 'openid profile',
  redirectUri: 'http://localhost:3000/api/callback',
  postLogoutRedirectUri: 'http://localhost:3000/',
  session: {
    cookieSecret: '<RANDOMLY_GENERATED_SECRET>',
    cookieLifetime: 60 * 60 * 8,
    storeAccessToken: true
  }
});
```

Then you could create a route (eg: `/pages/api/customers.js`) which can call an external API (eg: `https://api.mycompany.com`) using the user's `access_token`.

```js
import auth0 from '../../utils/auth0';

export default async function getCustomers(req, res) {
  try {
    const { accessToken } = await auth0.getSession(req);

    const apiClient = new MyApiClient(accessToken);
    return apiClient.getCustomers();
  } catch(error) {
    console.error(error)
    res.status(error.status || 500).end(error.message)
  }
}
```

### Requiring Authentication

If you have API routes for which you want to require the user to be authenticated you can use the `requireAuthentication` handler:

```js
import auth0 from '../../lib/auth0';

export default auth0.requireAuthentication(async function billingInfo(req, res) {
  const { user } = await auth0.getSession(req);
  res.json({
    email: user.email,
    country: 'United States',
    paymentMethod: 'Paypal'
  })
});
```

If the user is authenticated then your API route will simply execute, but if the user is not authenticated an error (401) will be returned:

```json
{
  "error": "not_authenticated",
  "description": "The user does not have an active session or is not authenticated"
}
```

## Documentation

### Cookies

All cookies will be set as `HttpOnly` cookies and will be forced to HTTPS (`Secure`) if the application is running with `NODE_ENV=production` and not running on localhost.

## Troubleshooting

### Error `id_token issued in the future, now 1570650460, iat 1570650461`

Increase the clock tolerance for id_token validation:

```js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  ...
  session: {
    ...
  },
  oidcClient: {
    // Eg: increase the tolerance to 10 seconds.
    clockTolerance: 10000
  }
});
```

## Contributing

Run NPM install first to install the dependencies of this project:

```bash
npm install
```

In order to build a release you can run the following commands and the output will be stored in the `dist` folder:

```bash
npm run clean
npm run lint
npm run build
```

Additionally you can also run tests:

```bash
npm run test
npm run test:watch
```

## Support + Feedback

This SDK is in Early Access and support is best effort. Open an issue in this repository to get help or provide feedback.

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

This project is licensed under the MIT license. See the [LICENSE](https://github.com/auth0/nextjs-auth0/blob/master/LICENSE) file for more info.
