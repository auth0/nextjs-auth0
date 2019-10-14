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
