## [1.0.0-beta.2](https://github.com/auth0/nextjs-auth0/tree/v1.0.0-beta.2) (2021-02-11)

**Additions**

- Added `afterRefetch` hook option to `handleProfile` to modify the session after refetching it.

## [1.0.0-beta.1](https://github.com/auth0/nextjs-auth0/tree/v1.0.0-beta.1) (2021-02-03)

**Additions**

- Added a new way to configure the custom profile url. Now it can be configured with an environment variable as well.

**Changes**

- The way to configure the custom login url has changed. Instead of passing it in every call to `withPageAuthRequired` now it can be configured with an environment variable.
- The Vercel configuration docs have been updated with the latest guidance.

**Fixes**

- Fixed a logout issue related to custom IdPs.

## [1.0.0-beta.0](https://github.com/auth0/nextjs-auth0/tree/v1.0.0-beta.0) (2021-01-14)

**Install**

```sh
npm install @auth0/nextjs-auth0@beta
```

**New features**

- New suite of frontend tools:
  - `useUser` hook and `UserProvider` to simplify checking and managing the user’s logged in state on the client.
  - `withPageAuthRequired` higher order component to protect client side routes.
- New `handleAuth` feature to reduce the amount of boilerplate required to set up the server side authentication handlers.
- Simpler server side API where creation of an SDK instance is handled by the SDK.

**Breaking changes**

For a full list of breaking changes and migration guide, checkout the [V1_MIGRATION_GUIDE.md](./V1_MIGRATION_GUIDE.md)

**Changes**

- AggregateError#message from `Issuer.discover` includes stack trace [#236](https://github.com/auth0/nextjs-auth0/pull/236) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Prevent caching the `/me` request [#233](https://github.com/auth0/nextjs-auth0/pull/233) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Added error handling to useUser [SDK-2236] [#229](https://github.com/auth0/nextjs-auth0/pull/229) ([Widcket](https://github.com/Widcket))
- Rename loading to isLoading [#222](https://github.com/auth0/nextjs-auth0/pull/222) ([Widcket](https://github.com/Widcket))
- Prepare application to be deployable with Vercel [#218](https://github.com/auth0/nextjs-auth0/pull/218) ([frederikprijck](https://github.com/frederikprijck))
- Added withCSRAuthRequired HOC [SDK-2120] [#209](https://github.com/auth0/nextjs-auth0/pull/209) ([Widcket](https://github.com/Widcket))
- [SDK-2057] Express mw tests [#191](https://github.com/auth0/nextjs-auth0/pull/191) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add withAuth HOC [SDK-2120] [#189](https://github.com/auth0/nextjs-auth0/pull/189) ([Widcket](https://github.com/Widcket))
- Add frontend hook tests [SDK-2117] [#188](https://github.com/auth0/nextjs-auth0/pull/188) ([Widcket](https://github.com/Widcket))
- Add frontend hook CH: Added [#187](https://github.com/auth0/nextjs-auth0/pull/187) ([Widcket](https://github.com/Widcket))

## [v0.16.0](https://github.com/auth0/nextjs-auth0/tree/v0.16.0) (2020-08-19)

- Updating dependencies with security issues
- Added the ability to force refreshing the `access_token` ([#147](https://github.com/auth0/nextjs-auth0/pull/147))

## [v0.15.0](https://github.com/auth0/nextjs-auth0/tree/v0.15.0) (2020-07-13)

- Improve redirect URI validation when double forward slashes are provided ([commit](https://github.com/auth0/nextjs-auth0/commit/88959971958e5c6ed5bd874828c97363d2224f74))
- Fix double encoding issue of `postLogoutRedirectUri` when using a different OIDC IdP ([#127](https://github.com/auth0/nextjs-auth0/pull/127))
- Keep previously set cookies in the `callbackHandler` ([#133](https://github.com/auth0/nextjs-auth0/pull/133))

## [v0.14.0](https://github.com/auth0/nextjs-auth0/tree/v0.14.0) (2020-07-08)

- Allow overriding the `returnTo` setting when signing out a user (in the `logoutHandler`)

## [v0.13.0](https://github.com/auth0/nextjs-auth0/tree/v0.13.0) (2020-05-15)

- Updated handlers to use `NextApiRequest` and `NextApiResponse`
- Automatically redirect to what is provided in the redirectTo querystring parameter, eg: `/api/login?redirectTo=/profile`

## [v0.12.0](https://github.com/auth0/nextjs-auth0/tree/v0.12.0) (2020-05-11)

- Support end_session_endpoint ([#102](https://github.com/auth0/nextjs-auth0/pull/102))
- Allow full control over the state generation
- Allow full control over the session creation

## [v0.11.0](https://github.com/auth0/nextjs-auth0/tree/v0.11.0) (2020-03-31)

- Make options optional in handlers ([#78](https://github.com/auth0/nextjs-auth0/pull/78))
- Add domain when clearing cookie ([#79](https://github.com/auth0/nextjs-auth0/pull/79))
- Add redirectTo support ([#81](https://github.com/auth0/nextjs-auth0/pull/81))

## [v0.10.0](https://github.com/auth0/nextjs-auth0/tree/v0.10.0) (2020-01-10)

- Add support to refetch the user in the profile handler.

## [v0.9.0](https://github.com/auth0/nextjs-auth0/tree/v0.9.0) (2020-01-08)

- Make `options` on the login handler optional

## [v0.8.0](https://github.com/auth0/nextjs-auth0/tree/v0.8.0) (2020-01-08)

- Improved TypeScript types
- Added support to automatically refresh access tokens

## [v0.7.0](https://github.com/auth0/nextjs-auth0/tree/v0.7.0) (2019-12-18)

- Add support for `SameSite` and set to `Lax` by default to mitigate CSRF attacks.

## [v0.6.0](https://github.com/auth0/nextjs-auth0/tree/v0.6.0) (2019-12-18)

- Add support for the `cookieDomain` option which allows you to share the session across subdomains.
- Fix the interface for the `handleLogin` method.
- Support sending a custom `state` to Auth0.

## [v0.5.0](https://github.com/auth0/nextjs-auth0/tree/v0.5.0) (2019-10-14)

- Added support for custom authorization parameters in the Login handler

## [v0.4.0](https://github.com/auth0/nextjs-auth0/tree/v0.4.0) (2019-10-10)

- Rename the `httpClient` to `oidcClient` setting to support more OIDC related settings.
- Added support for `id_token` leeway for when the time on your server is running behind on Auth0.
- Improve handling of `Secure` cookies. Don't force `Secure` cookies when running on localhost (to fix issues related to `next start`)

## [v0.3.0](https://github.com/auth0/nextjs-auth0/tree/v0.3.0) (2019-10-09)

- Fixed issue related to `audience` not being passed to the `/authorize` request
- Rename `useAuth0` to `initAuth0` to clear any confusion about React Hooks (this SDK does not provide a hook)
- Added a new handler to require authentication on API routes.

## [v0.2.0](https://github.com/auth0/nextjs-auth0/tree/v0.2.0) (2019-09-25)

- Added support for `storeRefreshToken` to persist the `refresh_token` in the session
- Added prettier
- Removed the need build time configuration

## [v0.1.0](https://github.com/auth0/nextjs-auth0/tree/v0.1.0) (2019-09-17)

Initial release.
