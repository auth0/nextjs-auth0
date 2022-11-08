# Change Log

## [v2.0.0-beta.3](https://github.com/auth0/nextjs-auth0/tree/v2.0.0-beta.3) (2022-11-08)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.0-beta.2...v2.0.0-beta.3)

**Fixed**
- Fix edge cookie support for Next < 13.0.1 [\#900](https://github.com/auth0/nextjs-auth0/pull/900) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.0.0-beta.2](https://github.com/auth0/nextjs-auth0/tree/v2.0.0-beta.2) (2022-11-02)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.0-beta.1...v2.0.0-beta.2)

**Added**
- At error cause to AT error when it's from a failed grant [\#878](https://github.com/auth0/nextjs-auth0/pull/878) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add logout options [\#877](https://github.com/auth0/nextjs-auth0/pull/877) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**
- Fix for new req.cookie interface [\#894](https://github.com/auth0/nextjs-auth0/pull/894) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.0.0-beta.1](https://github.com/auth0/nextjs-auth0/tree/v2.0.0-beta.1) (2022-10-21)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.0-beta.0...v2.0.0-beta.1)

**Fixed**
- status getter is not enumerable so needs to be added to NextResponse [\#875](https://github.com/auth0/nextjs-auth0/pull/875) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.0.0-beta.0](https://github.com/auth0/nextjs-auth0/tree/v2.0.0-beta.0) (2022-10-11)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.9.1...v2.0.0-beta.0)

- Change updateUser to updateSession [\#855](https://github.com/auth0/nextjs-auth0/pull/855) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add support for configuring the default handlers [\#840](https://github.com/auth0/nextjs-auth0/pull/840) ([Widcket](https://github.com/Widcket))
- Allow response customization in afterCallback [\#838](https://github.com/auth0/nextjs-auth0/pull/838) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Improved callback errors [\#835](https://github.com/auth0/nextjs-auth0/pull/835) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add support for configuring the built-in handlers [\#826](https://github.com/auth0/nextjs-auth0/pull/826) ([Widcket](https://github.com/Widcket))
- Prevent mixing named exports and own instances [\#825](https://github.com/auth0/nextjs-auth0/pull/825) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Default error handler [\#823](https://github.com/auth0/nextjs-auth0/pull/823) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Fix intermittent build issues [\#818](https://github.com/auth0/nextjs-auth0/pull/818) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add testing utility for generating session cookies [\#816](https://github.com/auth0/nextjs-auth0/pull/816) ([Widcket](https://github.com/Widcket))
- Next.js Middlware support [\#815](https://github.com/auth0/nextjs-auth0/pull/815) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Fix v1 cookie tests [\#810](https://github.com/auth0/nextjs-auth0/pull/810) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Do not store the ID token by default [\#809](https://github.com/auth0/nextjs-auth0/pull/809) ([Widcket](https://github.com/Widcket))
- Allow to override the user prop in server-side rendered pages [\#800](https://github.com/auth0/nextjs-auth0/pull/800) ([Widcket](https://github.com/Widcket))
- Improve API docs [\#796](https://github.com/auth0/nextjs-auth0/pull/796) ([Widcket](https://github.com/Widcket))
- Return 204 from /api/auth/me when logged out [\#791](https://github.com/auth0/nextjs-auth0/pull/791) ([Widcket](https://github.com/Widcket))
- Refactor session lifecycle [\#787](https://github.com/auth0/nextjs-auth0/pull/787) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Improve errors [\#782](https://github.com/auth0/nextjs-auth0/pull/782) ([Widcket](https://github.com/Widcket))

See [V2 Migration Guide](./V2_MIGRATION_GUIDE.md) for full details.

## [v1.9.2](https://github.com/auth0/nextjs-auth0/tree/v1.9.2) (2022-10-07)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.9.1...v1.9.2)

**Added**

- Fix updates to session not reflected in async `getServerSideProps` [\#843](https://github.com/auth0/nextjs-auth0/pull/843) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.9.1](https://github.com/auth0/nextjs-auth0/tree/v1.9.1) (2022-06-16)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.9.0...v1.9.1)

**Fixed**

- Add Props and Query to GetServerSidePropsWrapper type [\#731](https://github.com/auth0/nextjs-auth0/pull/731) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.9.0](https://github.com/auth0/nextjs-auth0/tree/v1.9.0) (2022-05-20)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.8.0...v1.9.0)

**Added**

- [SDK-3332] Constrain session lifecycle to `withPageAuthrequired` to avoid Next warning [\#664](https://github.com/auth0/nextjs-auth0/pull/664) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.8.0](https://github.com/auth0/nextjs-auth0/tree/v1.8.0) (2022-05-04)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.7.0...v1.8.0)

**Added**

- Add some useful props to the callback error [\#625](https://github.com/auth0/nextjs-auth0/pull/625) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Update to next 12 [\#612](https://github.com/auth0/nextjs-auth0/pull/612) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Fix Fast Refresh for WithPageAuthRequired [\#653](https://github.com/auth0/nextjs-auth0/pull/653) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Handle request errors on `useUser` hook [SDK-3227] [\#639](https://github.com/auth0/nextjs-auth0/pull/639) ([Widcket](https://github.com/Widcket))
- Add default to PageRoute type parameter [\#632](https://github.com/auth0/nextjs-auth0/pull/632) ([grantbdev](https://github.com/grantbdev))
- throw if you try to refresh with no rt [\#624](https://github.com/auth0/nextjs-auth0/pull/624) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Should be able to set rollingDuration as false (when rolling is false) [\#623](https://github.com/auth0/nextjs-auth0/pull/623) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Fix types in client-side `withPageAuthRequired` [\#574](https://github.com/auth0/nextjs-auth0/pull/574) ([slaypni](https://github.com/slaypni))

## [v1.7.0](https://github.com/auth0/nextjs-auth0/tree/v1.7.0) (2022-01-06)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.6.2...v1.7.0)

**Added**

- Include message body in 302 responses [\#564](https://github.com/auth0/nextjs-auth0/pull/564) ([michielvangendt](https://github.com/michielvangendt))

**Fixed**

- Honor configured sameSite in transient cookies so you can login to iframe using 'none' [\#571](https://github.com/auth0/nextjs-auth0/pull/571) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Cookies with samesite=none must have the secure attr set [\#570](https://github.com/auth0/nextjs-auth0/pull/570) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Improve types in server-side withPageAuthRequired [\#554](https://github.com/auth0/nextjs-auth0/pull/554) ([misoton665](https://github.com/misoton665))

## [v1.6.2](https://github.com/auth0/nextjs-auth0/tree/v1.6.2) (2021-12-16)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.6.1...v1.6.2)

**Fixed**

- Fix issue where error reporting wrong instanceof [\#543](https://github.com/auth0/nextjs-auth0/pull/543) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Security**

- Enforce configured host on user supplied returnTo [\#557](https://github.com/auth0/nextjs-auth0/pull/557) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v1.6.1](https://github.com/auth0/nextjs-auth0/tree/v1.6.1) (2021-10-13)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.6.0...v1.6.1)

**Fixed**

- [Snyk] Upgrade openid-client from 4.8.0 to 4.9.0 [\#518](https://github.com/auth0/nextjs-auth0/pull/518) ([snyk-bot](https://github.com/snyk-bot))

## [v1.6.0](https://github.com/auth0/nextjs-auth0/tree/v1.6.0) (2021-10-11)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.5.0...v1.6.0)

**Added**

- [SDK-2818] Export error classes [\#508](https://github.com/auth0/nextjs-auth0/pull/508) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-2529] Add ability to pass custom params to refresh grant and code exchange [\#507](https://github.com/auth0/nextjs-auth0/pull/507) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-2813] Add afterRefresh hook [\#506](https://github.com/auth0/nextjs-auth0/pull/506) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Fix types in server-side `withPageAuthRequired` [\#512](https://github.com/auth0/nextjs-auth0/pull/512) ([Widcket](https://github.com/Widcket))

## [1.5.0](https://github.com/auth0/nextjs-auth0/tree/v1.5.0) (2021-07-14)

**Added**

- Add IE11 support [#432](https://github.com/auth0/nextjs-auth0/pull/432) ([Widcket](https://github.com/Widcket))

## [1.4.2](https://github.com/auth0/nextjs-auth0/tree/v1.4.2) (2021-06-24)

**Fixed**

- Fix reflected XSS from the callback handler's error query parameter [CVE-2021-32702](https://github.com/auth0/nextjs-auth0/security/advisories/GHSA-954c-jjx6-cxv7) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.4.0](https://github.com/auth0/nextjs-auth0/tree/v1.4.0) (2021-06-03)

**Added**

- `withPageAuthRequired` CSR now adds `user` to wrapped component props [#405](https://github.com/auth0/nextjs-auth0/pull/405) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- env var substitutions now means you can define `AUTH0_BASE_URL` from `VERCEL_URL` in `next.config.js` [#404](https://github.com/auth0/nextjs-auth0/pull/404) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.3.1](https://github.com/auth0/nextjs-auth0/tree/v1.3.1) (2021-05-05)

**Fixed**

- Use `window.location.toString()` as the default `returnTo` value [#370](https://github.com/auth0/nextjs-auth0/pull/370) ([Widcket](https://github.com/Widcket))
- `returnTo` should be encoded as it contains url unsafe chars [#365](https://github.com/auth0/nextjs-auth0/pull/365) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.3.0](https://github.com/auth0/nextjs-auth0/tree/v1.3.0) (2021-03-26)

**Added**

- Organizations support [#343](https://github.com/auth0/nextjs-auth0/pull/343) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.2.0](https://github.com/auth0/nextjs-auth0/tree/v1.2.0) (2021-03-10)

**Added**

- Export `UserContext` for overriding default hook initialisation behaviour [#325](https://github.com/auth0/nextjs-auth0/pull/325) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- `returnTo` should respect application’s `basePath` configuration [#317](https://github.com/auth0/nextjs-auth0/pull/317) ([Widcket](https://github.com/Widcket))

## [1.1.0](https://github.com/auth0/nextjs-auth0/tree/v1.1.0) (2021-02-24)

**Added**

- Add `redirect_uri` option to callback handler [#298](https://github.com/auth0/nextjs-auth0/pull/298) ([mariano](https://github.com/mariano))

**Fixed**

- Chunked cookies should not exceed browser max [#301](https://github.com/auth0/nextjs-auth0/pull/301) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Cleanup unused cookies when switching between chunked and unchunked [#303](https://github.com/auth0/nextjs-auth0/pull/303) ([adamjmcgrath](https://github.com/adamjmcgrath))
- New tokens should be applied to existing session after handleProfile [#307](https://github.com/auth0/nextjs-auth0/pull/307) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [1.0.0](https://github.com/auth0/nextjs-auth0/tree/v1.0.0) (2021-02-15)

**New features**

- New suite of frontend tools:
  - `useUser` hook and `UserProvider` to simplify checking and managing the user’s logged in state on the client.
  - `withPageAuthRequired` higher order component to protect client side routes.
- New `handleAuth` feature to reduce the amount of boilerplate required to set up the server side authentication handlers.
- Simpler server side API where creation of an SDK instance is handled by the SDK.

**Breaking changes**

For a full list of breaking changes and migration guide, checkout the [V1_MIGRATION_GUIDE.md](./V1_MIGRATION_GUIDE.md)

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
