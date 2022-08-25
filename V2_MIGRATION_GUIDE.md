# V2 Migration Guide

Guide to migrating from `1.x` to `2.x`

- [`updateUser` has been added](#updateuser-has-been-added)
- [`getServerSidePropsWrapper` has been removed](#getserversidepropswrapper-has-been-removed)
- [Profile API route no longer returns a 401](#profile-api-route-no-longer-returns-a-401)

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

This will immediately serialise the session and write it to the cookie.

```js
// /pages/api/update-user
import { getSession, updateUser } from '@auth0/nextjs-auth0';

function myApiRoute(req, res) {
  const { user } = getSession(req, res);
  // The session is updated, serialized and the cookie is updated
  // everytime you call `updateUser`.
  updateUser(req, res, { ...user, foo: 'bar' });
  res.json({ success: true });
}
```

## `getServerSidePropsWrapper` has been removed

Because the process of modifying the session is now explicit, you no longer have to wrap `getServerSideProps` in `getServerSidePropsWrapper`.

### Before

```js
export const getServerSideProps = getServerSidePropsWrapper(async (ctx) => {
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
  const session = getSession(ctx.req, ctx.res);
  if (session) {
    // User is authenticated
  } else {
    // User is not authenticated
  }
};
```

## Profile API route no longer returns a 401

Previously the profile API route, by default at `/api/auth/me`, would return a 401 error when the user was not authenticated. While it was technically the right status code for the situation, it showed up in the browser console as an error. This API route will now return a 204 instead. Since 204 is a successful status code, it will not produce a console error.
