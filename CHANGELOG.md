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
