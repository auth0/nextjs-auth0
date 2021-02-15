# V1 Migration Guide

Guide to migrating from `0.x` to `1.x`

### Config changes

> Note: If you only use environment variables to configure the SDK, you don't need to create an instance of the SDK. You can use the named exports (`handleAuth`, `getSession`) directly from `@auth0/nextjs-auth` and they will lazily create an instance of the SDK for you, and configure it using the following [environment variables](https://auth0.github.io/nextjs-auth0/modules/config.html). See the [Basic setup](./EXAMPLES.md#basic-setup) as an example.

If you still want to create the SDK instance yourself, note that the configuration options have changed as follows.

- `domain` is now `issuerBaseURL` and should be a fully qualified url.
- `clientId` is now `clientID`
- `redirectUri` is now `routes.callback` and is a relative path, the full url is constructed using `baseURL`
- `postLogoutRedirectUri` is now `routes.postLogoutRedirect` and can be a relative path, the full url is constructed using `baseURL` if no host is provided.
- `scope` and `audience` are optional and should be passed to `authorizationParams`
- `session.cookieSecret` is now `secret`
- `session.cookieName` is now `session.name`
- `session.cookieSameSite` is now `session.cookie.sameSite`
- `session.cookieLifetime` is now `session.rollingDuration` and defaults to 24 hrs rolling and 7 days absolute
- `session.cookiePath` is now `session.cookie.path` and defaults to `'/'`
- `session.cookieDomain` is now `session.cookie.domain`
- `session.storeIdToken`, `session.storeAccessToken`, `session.storeRefreshToken` are no longer options. All tokens are stored by default, to remove anything from the session see [the afterCallback option in handleCallback](https://auth0.github.io/nextjs-auth0/modules/handlers_callback.html#modify-the-session-after-login).
- `oidcClient.httpTimeout` is now `httpTimeout` and defaults to 5000 ms
- `oidcClient.clockTolerance` is now `clockTolerance` defined in secs and defaults to 60 secs

#### Before

```js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  domain: 'my-tenant.auth0.com',
  clientId: 'MY_CLIENT_ID',
  clientSecret: 'MY_CLIENT_SECRET',
  scope: 'openid profile',
  audience: 'MY_AUDIENCE',
  redirectUri: 'http://localhost:3000/api/callback',
  postLogoutRedirectUri: 'http://localhost:3000/',
  session: {
    cookieSecret: 'some_very_long_secret_string',
    cookieLifetime: 60 * 60 * 8,
    storeIdToken: false,
    storeRefreshToken: false,
    storeAccessToken: false
  },
  oidcClient: {
    clockTolerance: 10000,
    httpTimeout: 2500
  }
});
```

#### After

```js
import { initAuth0 } from '@auth0/nextjs-auth0';

export default initAuth0({
  baseURL: 'http://localhost:3000',
  issuerBaseURL: 'https://my-tenant.auth0.com',
  clientID: 'MY_CLIENT_ID',
  clientSecret: 'MY_CLIENT_SECRET',
  secret: 'some_very_long_secret_string',
  clockTolerance: 60,
  httpTimeout: 5000,
  authorizationParams: {
    scope: 'openid profile email',
    audience: 'MY_AUDIENCE'
  },
  routes: {
    callback: '/api/callback',
    postLogoutRedirect: '/'
  },
  session: {
    rollingDuration: 60 * 60 * 24,
    absoluteDuration: 60 * 60 * 24 * 7
  }
});
```

See the API docs for a [full list of configuration options](https://auth0.github.io/nextjs-auth0/modules/config.html).

### getSession

`getSession` now requires a response as well as a request argument (any updates you make to the session object will now be persisted).

#### Before

```js
// pages/api/shows.js
import auth0 from '../../lib/auth0';

export default function shows(req, res) {
  const session = auth0.getSession(req);
  // ...
}
```

#### After

```js
// pages/api/shows.js
import auth0 from '../../lib/auth0';

export default function shows(req, res) {
  const session = auth0.getSession(req, res); // Note: the extra argument
  // ...
}
```

See the [getSession docs](https://auth0.github.io/nextjs-auth0/modules/session_get_session.html).

### getAccessToken

`tokenCache` has been removed in favor of a single `getAccessToken` method.

### Before

```js
// pages/api/shows.js
import auth0 from '../../lib/auth0';

export default async function shows(req, res) {
  const tokenCache = auth0.tokenCache(req, res);
  const { accessToken } = await tokenCache.getAccessToken({
    scopes: ['read:shows']
  });
  // ...
}
```

### After

```js
// pages/api/shows.js
import auth0 from '../../lib/auth0';

export default async function shows(req, res) {
  const { accessToken } = await auth0.getAccessToken(req, res, {
    scopes: ['read:shows']
  });
  // ...
}
```

See the [getAccessToken docs](https://auth0.github.io/nextjs-auth0/modules/session_get_access_token.html).

### handleLogin

The options passed to `handleLogin` have changed.

- `authParams` is now `authorizationParams`
- `redirectTo` is now `returnTo`

#### Before

```js
// pages/api/login.js
import auth0 from '../../utils/auth0';

export default async function login(req, res) {
  try {
    await auth0.handleLogin(req, res, {
      authParams: {
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope',
        foo: 'bar'
      },
      redirectTo: '/custom-url'
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

#### After

```js
// pages/api/login.js
import auth0 from '../../utils/auth0';

export default async function login(req, res) {
  try {
    await auth0.handleLogin(req, res, {
      authorizationParams: {
        login_hint: 'foo@acme.com',
        ui_locales: 'nl',
        scope: 'some other scope',
        foo: 'bar'
      },
      returnTo: '/custom-url'
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

See the [handleLogin docs](https://auth0.github.io/nextjs-auth0/modules/handlers_login.html).

### handleLogout

The options passed to `handleLogout` have changed.

- `redirectTo` is now `returnTo`

#### Before

```js
// pages/api/logout.js
import auth0 from '../../utils/auth0';

export default async function logout(req, res) {
  try {
    await auth0.handleLogout(req, res, {
      redirectTo: '/custom-url'
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

#### After

```js
// pages/api/logout.js
import auth0 from '../../utils/auth0';

export default async function logout(req, res) {
  try {
    await auth0.handleLogout(req, res, {
      returnTo: '/custom-url'
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

See the [handleLogout docs](https://auth0.github.io/nextjs-auth0/modules/handlers_logout.html).

### handleCallback

The options passed to `handleCallback` have changed.

- `onUserLoaded` is now `afterCallback`

#### Before

```js
// pages/api/callback.js
import auth0 from '../../utils/auth0';

export default async function callback(req, res) {
  try {
    await auth0.handleCallback(req, res, {
      async onUserLoaded(req, res, session, state) {
        return session;
      }
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

#### After

```js
// pages/api/callback.js
import auth0 from '../../utils/auth0';

export default async function callback(req, res) {
  try {
    await auth0.handleCallback(req, res, {
      async afterCallback(req, res, session, state) {
        return session;
      }
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
```

See the [handleCallback docs](https://auth0.github.io/nextjs-auth0/modules/handlers_callback.html).
