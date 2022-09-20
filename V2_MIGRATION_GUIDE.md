# V2 Migration Guide

Guide to migrating from `1.x` to `2.x`

- [`getSession` now returns a `Promise`](#getsession-now-returns-a-promise)
- [`updateUser` has been added](#updateuser-has-been-added)
- [`getServerSidePropsWrapper` has been removed](#getserversidepropswrapper-has-been-removed)
- [Profile API route no longer returns a 401](#profile-api-route-no-longer-returns-a-401)
- [The ID token is no longer stored by default](#the-id-token-is-no-longer-stored-by-default)
- [Override default error handler](#override-default-error-handler)

## `getSession` now returns a `Promise`

### Before

```js
// /pages/api/my-api
import { getSession } from '@auth0/nextjs-auth0';

function myApiRoute(req, res) {
  const session = getSession(req, res);
  // ...
}
```

### After

```js
// /pages/api/my-api
import { getSession } from '@auth0/nextjs-auth0';

async function myApiRoute(req, res) {
  const session = await getSession(req, res);
  // ...
}
```

## `updateUser` has been added

### Before

Previously your application could make modifications to the session during the lifecycle of the request and those updates would be saved implicitly when the response's headers were written, just before delivering the response to the client.

```js
// /pages/api/update-user
import { getSession } from '@auth0/nextjs-auth0';

function myApiRoute(req, res) {
  const { user } = getSession(req, res);
  user.foo = 'bar';
  res.json({ success: true });
}
// The updated session is serialized and the cookie is updated
// when the cookie headers are written to the response.
```

### After

We've introduced a new `updateUser` method which must be explicitly invoked in order to update the session's user.

This will immediately serialise the session, write it to the cookie and return a `Promise`.

```js
// /pages/api/update-user
import { getSession, updateUser } from '@auth0/nextjs-auth0';

async function myApiRoute(req, res) {
  const { user } = await getSession(req, res);
  // The session is updated, serialized and the cookie is updated
  // everytime you call `updateUser`.
  await updateUser(req, res, { ...user, foo: 'bar' });
  res.json({ success: true });
}
```

## `getServerSidePropsWrapper` has been removed

Because the process of modifying the session is now explicit, you no longer have to wrap `getServerSideProps` in `getServerSidePropsWrapper`.

### Before

```js
export const getServerSideProps = getServerSidePropsWrapper((ctx) => {
  const session = getSession(ctx.req, ctx.res);
  if (session) {
    // User is authenticated
  } else {
    // User is not authenticated
  }
});
```

### After

```js
export const getServerSideProps = async (ctx) => {
  const session = await getSession(ctx.req, ctx.res);
  if (session) {
    // User is authenticated
  } else {
    // User is not authenticated
  }
};
```

## Profile API route no longer returns a 401

Previously the profile API route, by default at `/api/auth/me`, would return a 401 error when the user was not authenticated. While it was technically the right status code for the situation, it showed up in the browser console as an error. This API route will now return a 204 instead. Since 204 is a successful status code, it will not produce a console error.

## The ID token is no longer stored by default

Previously the ID token would be stored in the session cookie, making the cookie unnecessarily large. Removing it required adding an `afterCallback` hook to the callback API route, and an `afterRefresh` hook to `getAccessToken()` –when using refresh tokens.

Now the SDK will not store it by default. If you had been using hooks to strip it away, you can safely remove those.

You can choose to store it by setting either the `session.storeIDToken` config property or the `AUTH0_SESSION_STORE_ID_TOKEN` environment variable to `true`.

## Override default error handler

You can now set the default error handler for the auth routes in a single place.

```js
export default handleAuth({
  async login(req, res) {
    try {
      await handleLogin(req, res);
    } catch (error) {
      errorLogger(error);
      res.status(error.status || 500).end();
    }
  },
  async callback(req, res) {
    try {
      await handleLogin(req, res);
    } catch (error) {
      errorLogger(error);
      res.status(error.status || 500).end();
    }
  }
  // ...
});
```

### After

```js
export default handleAuth({
  onError(req, res, error) {
    errorLogger(error);
    // You can finish the response yourself if you want to customise
    // the status code or redirect the user
    // res.writeHead(302, {
    //     Location: '/cusotm-error-page'
    // });
    // res.end();
  }
});
```
