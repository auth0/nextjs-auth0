# Change Log

## [v4.15.0](https://github.com/auth0/nextjs-auth0/tree/v4.15.0) (2026-02-09)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.14.1...v4.15.0)

**Added**
- feat: MFA APIs [\#2502](https://github.com/auth0/nextjs-auth0/pull/2502) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: Base MFA support [\#2480](https://github.com/auth0/nextjs-auth0/pull/2480) ([tusharpandey13](https://github.com/tusharpandey13))
- Add TTL to /auth/access-token and optional full client response [\#2505](https://github.com/auth0/nextjs-auth0/pull/2505) ([nandan-bhat](https://github.com/nandan-bhat))

## [v4.14.1](https://github.com/auth0/nextjs-auth0/tree/v4.14.1) (2026-01-24)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.14.0...v4.14.1)

**Fixed**
- fix: do not throw ERR_JWE_DECRYPTION_FAILED, but catch it and ignore the cookie. [\#2487](https://github.com/auth0/nextjs-auth0/pull/2487) ([frederikprijck](https://github.com/frederikprijck))
- fix: avoid headers.append error when using getAccessToken with refresh in Next.js 16 proxy  [\#2495](https://github.com/auth0/nextjs-auth0/pull/2495) ([nandan-bhat](https://github.com/nandan-bhat))
- fix: removed un-intended class/type exports from the SDK [\#2475](https://github.com/auth0/nextjs-auth0/pull/2475) ([nandan-bhat](https://github.com/nandan-bhat))

## [v4.14.0](https://github.com/auth0/nextjs-auth0/tree/v4.14.0) (2025-12-15)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.13.3...v4.14.0)

**Added**
- feat: Custom Token Exchange [\#2453](https://github.com/auth0/nextjs-auth0/pull/2453) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.13.3](https://github.com/auth0/nextjs-auth0/tree/v4.13.3) (2025-12-12)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.13.2...v4.13.3)

**Fixed**
- bugfix: session write not happening for pages router with chunked cookies [\#2447](https://github.com/auth0/nextjs-auth0/pull/2447) ([tusharpandey13](https://github.com/tusharpandey13))

**Security**
- Security: Update Next.js peer dependencies for CVE-2025-55184 and CVE-2025-55183 [\#2457](https://github.com/auth0/nextjs-auth0/pull/2457) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.13.2](https://github.com/auth0/nextjs-auth0/tree/v4.13.2) (2025-12-05)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.13.1...v4.13.2)

**Changed**
- Updated peer dependency
  - Next: `^14.2.25 || ~15.0.5 || ~15.1.9 || ~15.2.6 || ~15.3.6 || ~15.4.8 || ~15.5.7 || ^16.0.7`
  - React: `^18.0.0 || ~19.0.1 ||  ~19.1.2 || ^19.2.1`
  - React-DOM: `^18.0.0 || ~19.0.1 ||  ~19.1.2 || ^19.2.1`

## [v4.13.1](https://github.com/auth0/nextjs-auth0/tree/v4.13.1) (2025-11-19)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.13.0...v4.13.1)

**Added**
- docs: Add docs for silent authentication [\#2422](https://github.com/auth0/nextjs-auth0/pull/2422) ([tusharpandey13](https://github.com/tusharpandey13))

**Fixed**
- fix: broken next-16 app when basePath is used [\#2424](https://github.com/auth0/nextjs-auth0/pull/2424) ([nandan-bhat](https://github.com/nandan-bhat))

## [v4.13.0](https://github.com/auth0/nextjs-auth0/tree/v4.13.0) (2025-11-17)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.12.1...v4.13.0)

**Added**
- feat: add support `scopes` parameter for connected accounts [\#2407](https://github.com/auth0/nextjs-auth0/pull/2407) ([guabu](https://github.com/guabu))
- Adding support for Next 16 [\#2405](https://github.com/auth0/nextjs-auth0/pull/2405) ([nandan-bhat](https://github.com/nandan-bhat))

**Fixed**
- fix: merge sessionChanges before finalizing session after refresh (#2401) [\#2414](https://github.com/auth0/nextjs-auth0/pull/2414) (Clone of #2401 by [wolfgangGoedel ](https://github.com/wolfgangGoedel))
- fix: prevent OAuth parameter injection via returnTo (#2381) [\#2413](https://github.com/auth0/nextjs-auth0/pull/2413) (Clone of #2381 by [MegaManSec](https://github.com/MegaManSec))

## [v4.12.1](https://github.com/auth0/nextjs-auth0/tree/v4.12.1) (2025-11-13)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.12.0...v4.12.1)

**Changed**
- Remove TokenRequestCache when calling getAccessToken

## [v4.12.0](https://github.com/auth0/nextjs-auth0/tree/v4.12.0) (2025-11-07)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.11.1...v4.12.0)

**Added**
- feat: Proxy handler support enabling My Account and My Org [\#2400](https://github.com/auth0/nextjs-auth0/pull/2400) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.11.1](https://github.com/auth0/nextjs-auth0/tree/v4.11.1) (2025-10-31)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.11.0...v4.11.1)

**Fixed**
- fix: DPoP nonce retry on auth code callback [\#2391](https://github.com/auth0/nextjs-auth0/pull/2391) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: append intl headers in with-next-intl instead of overwrite [\#2386](https://github.com/auth0/nextjs-auth0/pull/2386) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: make sure `beforeSessionSaved` hook gets the updated token after refresh [\#2387](https://github.com/auth0/nextjs-auth0/pull/2387) ([tusharpandey13](https://github.com/tusharpandey13))
- Fix `updateSession` and header overwrite issues [\#2330](https://github.com/auth0/nextjs-auth0/pull/2330) ([tusharpandey13](https://github.com/tusharpandey13))
- bugfix: Remove React dependency from server helpers to fix edge runtime bundling [\#2329](https://github.com/auth0/nextjs-auth0/pull/2329) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.11.0](https://github.com/auth0/nextjs-auth0/tree/v4.11.0) (2025-10-18)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.10.0...v4.11.0)

**Added**
- feat: Add DPoP (Demonstrating Proof-of-Possession) [\#2357](https://github.com/auth0/nextjs-auth0/pull/2357) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: add support for connected accounts [\#2344](https://github.com/auth0/nextjs-auth0/pull/2344) ([guabu](https://github.com/guabu))
- Add support for access tokens with difference audiences (MRRT) [\#2333](https://github.com/auth0/nextjs-auth0/pull/2333) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix: ensure Connected Accounts use fetcher to properly use DPoP [\#2366](https://github.com/auth0/nextjs-auth0/pull/2366) ([frederikprijck](https://github.com/frederikprijck))
- fix: ensure fetcher honors token_type [\#2365](https://github.com/auth0/nextjs-auth0/pull/2365) ([frederikprijck](https://github.com/frederikprijck))
- fix: address typos in comments and examples [\#2347](https://github.com/auth0/nextjs-auth0/pull/2347) ([frederikprijck](https://github.com/frederikprijck))

## [v4.10.0](https://github.com/auth0/nextjs-auth0/tree/v4.10.0) (2025-09-16)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.9.0...v4.10.0)

**Added**
- feat: control sending `id_token_hint` in OIDC logout URL [\#2300](https://github.com/auth0/nextjs-auth0/pull/2300) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: Allow access token grant type for federated connections [\#2240](https://github.com/auth0/nextjs-auth0/pull/2240) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: add federated logout [\#2313](https://github.com/auth0/nextjs-auth0/pull/2313) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: Add organizations [\#2282](https://github.com/auth0/nextjs-auth0/pull/2282) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: add support for backchannel authentication [\#2261](https://github.com/auth0/nextjs-auth0/pull/2261) ([guabu](https://github.com/guabu))

**Changed**
- feat: simplify PAR parameter handling by removing redundant filtering [\#2298](https://github.com/auth0/nextjs-auth0/pull/2298) ([tusharpandey13](https://github.com/tusharpandey13))

**Fixed**
- fix: Remove unsafe type assertion in withPageAuthRequired HOC [\#2305](https://github.com/auth0/nextjs-auth0/pull/2305) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: parameter name of requested_expiry [\#2304](https://github.com/auth0/nextjs-auth0/pull/2304) ([guabu](https://github.com/guabu))
- fix: ensure to mark StartInteractiveLoginOptions as optional [\#2272](https://github.com/auth0/nextjs-auth0/pull/2272) ([frederikprijck](https://github.com/frederikprijck))

## [v4.9.0](https://github.com/auth0/nextjs-auth0/tree/v4.9.0) (2025-08-01)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.8.0...v4.9.0)

**Added**
- feat: Allow configuring transaction cookie maxAge [\#2245](https://github.com/auth0/nextjs-auth0/pull/2245) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: Add flag to control parallel transactions [\#2244](https://github.com/auth0/nextjs-auth0/pull/2244) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: add support for `withApiAuthRequired` helper [\#2230](https://github.com/auth0/nextjs-auth0/pull/2230) ([guabu](https://github.com/guabu))
- feat: add `withPageAuthRequired` for server [\#2207](https://github.com/auth0/nextjs-auth0/pull/2207) ([guabu](https://github.com/guabu))

**Fixed**
- bugfix: respect path configuration when deleting cookies [\#2250](https://github.com/auth0/nextjs-auth0/pull/2250) ([tusharpandey13](https://github.com/tusharpandey13))
- bugfix: Clear cookies with the correct path when basePath is used [\#2232](https://github.com/auth0/nextjs-auth0/pull/2232) ([tusharpandey13](https://github.com/tusharpandey13))
- bugfix: Fix `clientAssertionSigningKey` type mismatch [\#2243](https://github.com/auth0/nextjs-auth0/pull/2243) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: correctly handle expired JWE's in cookies [\#2082](https://github.com/auth0/nextjs-auth0/pull/2082) ([frederikprijck](https://github.com/frederikprijck))

**Security**
- chore: pin eslint-config-prettier and eslint-plugin-prettier versions to prevent malicious package installation [\#2239](https://github.com/auth0/nextjs-auth0/pull/2239) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.8.0](https://github.com/auth0/nextjs-auth0/tree/v4.8.0) (2025-07-03)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.7.0...v4.8.0)

**Added**
- feat: Add alternate logout strategy [\#2203](https://github.com/auth0/nextjs-auth0/pull/2203) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: add `withPageAuthRequired` for protecting pages client side [\#2193](https://github.com/auth0/nextjs-auth0/pull/2193) ([guabu](https://github.com/guabu))

**Fixed**
- Use `max-age=0` to delete cookie [\#2200](https://github.com/auth0/nextjs-auth0/pull/2200) ([guabu](https://github.com/guabu))
- feat: update id_token when a new Access Token is fetched [\#2189](https://github.com/auth0/nextjs-auth0/pull/2189) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.7.0](https://github.com/auth0/nextjs-auth0/tree/v4.7.0) (2025-06-20)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.6.1...v4.7.0)

**Added**
- feat: support basePath configuration [\#2167](https://github.com/auth0/nextjs-auth0/pull/2167) ([guabu](https://github.com/guabu))

**Fixed**
- fix: typo in warning message [\#2169](https://github.com/auth0/nextjs-auth0/pull/2169) ([J-Amberg](https://github.com/J-Amberg))
- fix: handle authorization code grant request errors [\#2175](https://github.com/auth0/nextjs-auth0/pull/2175) ([guabu](https://github.com/guabu))
- fix: Properly configure SDK to be distributed as ESM [\#2171](https://github.com/auth0/nextjs-auth0/pull/2171) ([frederikprijck](https://github.com/frederikprijck))
- fix: consistently treat returnTo parameter as an absolute path [\#2185](https://github.com/auth0/nextjs-auth0/pull/2185) ([guabu](https://github.com/guabu))

**Changed**
- Export filterDefaultIdTokenClaims and update beforeSessionSaved docs [\#2119](https://github.com/auth0/nextjs-auth0/pull/2119) ([frederikprijck](https://github.com/frederikprijck))
- return a 204 from the profile endpoint when unauthenticated (opt-in) [\#2159](https://github.com/auth0/nextjs-auth0/pull/2159) ([guabu](https://github.com/guabu))
- remove unnecessary error logs [\#2179](https://github.com/auth0/nextjs-auth0/pull/2179) ([guabu](https://github.com/guabu))
- Bump msw from 2.7.5 to 2.9.0 [\#2139](https://github.com/auth0/nextjs-auth0/pull/2139) ([dependabot](https://github.com/dependabot))
- Bump msw from 2.9.0 to 2.10.2 [\#2153](https://github.com/auth0/nextjs-auth0/pull/2153) ([dependabot](https://github.com/dependabot))
- Bump oauth4webapi from 3.5.1 to 3.5.2 [\#2154](https://github.com/auth0/nextjs-auth0/pull/2154) ([dependabot](https://github.com/dependabot))
- Bump oauth4webapi from 3.5.2 to 3.5.3 [\#2177](https://github.com/auth0/nextjs-auth0/pull/2177) ([dependabot](https://github.com/dependabot))

## [v4.6.1](https://github.com/auth0/nextjs-auth0/tree/v4.6.1) (2025-06-04)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.6.0...v4.6.1)

**Fixed**
- Fixes CVE-2025-48947
- Fix Missing idToken during Session Migration from v3 to v4 #2116 [\#2120](https://github.com/auth0/nextjs-auth0/pull/2120) ([KentoMoriwaki](https://github.com/KentoMoriwaki))
- fix(session): prevent accidental deletion of legacy-named session cookie [\#2114](https://github.com/auth0/nextjs-auth0/pull/2114) ([nandan-bhat](https://github.com/nandan-bhat))
- fix(client): add type-safe return for getAccessToken [\#2115](https://github.com/auth0/nextjs-auth0/pull/2115) ([nandan-bhat](https://github.com/nandan-bhat))

## [v4.6.0](https://github.com/auth0/nextjs-auth0/tree/v4.6.0) (2025-05-21)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.5.1...v4.6.0)

**Added**
- feature/conditionally update session handleAccessToken [\#2054](https://github.com/auth0/nextjs-auth0/pull/2054) ([tusharpandey13](https://github.com/tusharpandey13))
- Add missing support for legacy chunked cookies [\#2071](https://github.com/auth0/nextjs-auth0/pull/2071) ([tusharpandey13](https://github.com/tusharpandey13))

**Changed**
- Update middleware combination example to prevent unintended backend execution [\#2076](https://github.com/auth0/nextjs-auth0/pull/2076) ([tusharpandey13](https://github.com/tusharpandey13))

**Fixed**
- Bugfix: Add clockTolerance to cookie decryption [\#2097](https://github.com/auth0/nextjs-auth0/pull/2097) ([tusharpandey13](https://github.com/tusharpandey13))
- Fix stacking transaction cookies [\#2077](https://github.com/auth0/nextjs-auth0/pull/2077) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.5.1](https://github.com/auth0/nextjs-auth0/tree/v4.5.1) (2025-04-29)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.5.0...v4.5.1)

**Security**
- fix: Ensure JWE expires as expected [\#2040](https://github.com/auth0/nextjs-auth0/pull/2040) ([frederikprijck](https://github.com/frederikprijck))

## [v4.5.0](https://github.com/auth0/nextjs-auth0/tree/v4.5.0) (2025-04-25)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.4.2...v4.5.0)

**Added**
- Extensive Cookie Configuration [\#2059](https://github.com/auth0/nextjs-auth0/pull/2059) ([tusharpandey13](https://github.com/tusharpandey13))
- Allow refresh: true in getAccessToken() [\#2055](https://github.com/auth0/nextjs-auth0/pull/2055) ([tusharpandey13](https://github.com/tusharpandey13))
- Allow SWR mutation in useUser hook [\#2045](https://github.com/auth0/nextjs-auth0/pull/2045) ([tusharpandey13](https://github.com/tusharpandey13))

**Changed**
- Update README regarding access-token endpoint [\#2044](https://github.com/auth0/nextjs-auth0/pull/2044) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- Update tests for getAccessToken refresh flow [\#2068](https://github.com/auth0/nextjs-auth0/pull/2068) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: make configuration validation not throw [\#2034](https://github.com/auth0/nextjs-auth0/pull/2034) ([tusharpandey13](https://github.com/tusharpandey13))
- feat: ensure cookie path is configurable [\#2050](https://github.com/auth0/nextjs-auth0/pull/2050) ([frederikprijck](https://github.com/frederikprijck))

## [v4.4.2](https://github.com/auth0/nextjs-auth0/tree/v4.4.2) (2025-04-08)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.4.1...v4.4.2)

**Revert**
- revert: fix: Properly configure SDK to be distributed as ESM [\#2046](https://github.com/auth0/nextjs-auth0/pull/2046) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix: Add id_token_hint on logout [\#2041](https://github.com/auth0/nextjs-auth0/pull/2041) ([frederikprijck](https://github.com/frederikprijck))

## [v4.4.1](https://github.com/auth0/nextjs-auth0/tree/v4.4.1) (2025-04-03)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.4.0...v4.4.1)

**Fixed**
- fix: Properly configure SDK to be distributed as ESM [\#2028](https://github.com/auth0/nextjs-auth0/pull/2028) ([frederikprijck](https://github.com/frederikprijck))
- Fix broken links in jsdocs [\#2031](https://github.com/auth0/nextjs-auth0/pull/2031) ([frederikprijck](https://github.com/frederikprijck))
- fix: Throw ConfigurationError when invalid Auth0Client configuration [\#2026](https://github.com/auth0/nextjs-auth0/pull/2026) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.4.0](https://github.com/auth0/nextjs-auth0/tree/v4.4.0) (2025-04-01)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.3.0...v4.4.0)

**Added**
- Add note about access-token endpoint to README [\#2020](https://github.com/auth0/nextjs-auth0/pull/2020) ([frederikprijck](https://github.com/frederikprijck))
- Add support for Connection Access Token [\#2010](https://github.com/auth0/nextjs-auth0/pull/2010) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- fix: Delete legacy cookie once v4 cookie is set [\#2019](https://github.com/auth0/nextjs-auth0/pull/2019) ([frederikprijck](https://github.com/frederikprijck))
- fix: Ensure to delete cookies when switching from single to chunks and vica versa [\#2013](https://github.com/auth0/nextjs-auth0/pull/2013) ([frederikprijck](https://github.com/frederikprijck))
- fix: Clean up cookie chunks when cookie size shrinks [\#2014](https://github.com/auth0/nextjs-auth0/pull/2014) ([frederikprijck](https://github.com/frederikprijck))
- fix: use NEXT_PUBLIC_PROFILE_ROUTE in Auth0Provider [\#2021](https://github.com/auth0/nextjs-auth0/pull/2021) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: Ensure to pass-through enableAccessTokenEndpoint [\#2015](https://github.com/auth0/nextjs-auth0/pull/2015) ([frederikprijck](https://github.com/frederikprijck))
- fix: Remove obsolete warning about cookie-size [\#2012](https://github.com/auth0/nextjs-auth0/pull/2012) ([frederikprijck](https://github.com/frederikprijck))

## [v4.3.0](https://github.com/auth0/nextjs-auth0/tree/v4.3.0) (2025-03-28)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.2.1...v4.3.0)

**Added**
- Access Token Exposure Control [\#1979](https://github.com/auth0/nextjs-auth0/pull/1979) ([tusharpandey13](https://github.com/tusharpandey13))
- Cookie chunking support [\#1975](https://github.com/auth0/nextjs-auth0/pull/1975) ([tusharpandey13](https://github.com/tusharpandey13))
- Add idToken to TokenSet in SessionData [\#1978](https://github.com/auth0/nextjs-auth0/pull/1978) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.2.1](https://github.com/auth0/nextjs-auth0/tree/v4.2.1) (2025-03-24)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.2.0...v4.2.1)

**Changed**
- Bump next in SDK as well as examples [\#1992](https://github.com/auth0/nextjs-auth0/pull/1992) ([frederikprijck](https://github.com/frederikprijck))

## [v4.2.0](https://github.com/auth0/nextjs-auth0/tree/v4.2.0) (2025-03-23)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.1.0...v4.2.0)

**Security**
- Enforce nextjs peerDependency to 14.2.25 and 15.2.3 [\#1988](https://github.com/auth0/nextjs-auth0/pull/1988) ([frederikprijck](https://github.com/frederikprijck))

The above security fix was done to help prevent customers being vulnerable to [Authorization Bypass in Next.js Middleware](https://github.com/advisories/GHSA-f82v-jwr5-mffw).

## [v4.1.0](https://github.com/auth0/nextjs-auth0/tree/v4.1.0) (2025-03-13)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.0.3...v4.1.0)

**Added**
- Programmatic PAR [\#1946](https://github.com/auth0/nextjs-auth0/pull/1946) ([tusharpandey13](https://github.com/tusharpandey13))

**Fixed**
- fix: stop importing named export from package.json [\#1962](https://github.com/auth0/nextjs-auth0/pull/1962) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.0.3](https://github.com/auth0/nextjs-auth0/tree/v4.0.3) (2025-03-10)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.0.2...v4.0.3)

**Fixed**
- Fix route matching when Next.js trailingSlash is enabled [\#1948](https://github.com/auth0/nextjs-auth0/pull/1948) ([tusharpandey13](https://github.com/tusharpandey13))
- fix: allow appBaseUrl to not be the root [\#1941](https://github.com/auth0/nextjs-auth0/pull/1941) ([frederikprijck](https://github.com/frederikprijck))

## [v4.0.2](https://github.com/auth0/nextjs-auth0/tree/v4.0.2) (2025-02-19)
[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.0.1...v4.0.2)

**Changed**
- Update API DOCs link on the README.md [\#1914](https://github.com/auth0/nextjs-auth0/pull/1914) ([nandan-bhat](https://github.com/nandan-bhat))
- Updating API DOCs [\#1913](https://github.com/auth0/nextjs-auth0/pull/1913) ([nandan-bhat](https://github.com/nandan-bhat))

**Fixed**
- fix: read and migrate v3 session format to v4 [\#1923](https://github.com/auth0/nextjs-auth0/pull/1923) ([guabu](https://github.com/guabu))
- fix/updateV4MigrationGuide [\#1925](https://github.com/auth0/nextjs-auth0/pull/1925) ([tusharpandey13](https://github.com/tusharpandey13))

## [v4.0.1](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.1) (2025-02-12)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v4.0.0...v4.0.1)

**Fixed**

- fix: sanitize the returnTo parameter to prevent open redirect vulnerabilities. [\#1897](https://github.com/auth0/nextjs-auth0/pull/1897) ([guabu](https://github.com/guabu))

## [v3.6.0](https://github.com/auth0/nextjs-auth0/tree/v3.6.0) (2025-01-31)

This is a maintainance release for V3 of the SDK.  
V4 supports Next.JS 15 and React 19 and is published on [npm](https://www.npmjs.com/package/@auth0/nextjs-auth0)!  
We will continue to add features and security upgrades in V4 going further. Please migrate to V4 for a better experience.

**Security**

- [bump jshttp/cookie from 0.6.0 to 0.7.1](https://github.com/auth0/nextjs-auth0/pull/1778)

## [v4.0.0](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0) (2024-01-30)

**⚠️ BREAKING CHANGES**.

Significant updates have been introduced in this release. Please refer to the V3 → V4 [MIGRATION GUIDE](./V4_MIGRATION_GUIDE.md) for details on upgrading.

**Fixed**

- chore: add telemetry and options to disable in #1864
- chore: reduce session lifetime defaults in #1869
- fix: persist access token scope in tokenset in #1870
- chore: in-memory cache for authorization server metadata in #1871

## [v4.0.0-beta.14](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.14) (2024-01-06)

**Fixed**

- fix: propagate session data updates within the same request (fixes: #1841)
- chore: export SessionDataStore and LogoutToken types (closes: #1852)
- feat: add generateSessionCookie testing helper (closes: #1857)

## [v4.0.0-beta.13](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.13) (2024-12-20)

**Fixed**

- chore: refresh the token set when calling getAccessToken instead of the middleware (fixes: #1851 and #1841)
- feat: add idToken to beforeSessionSaved hook (closes: #1840)
- fix: ensure builds succeed without AUTH0_DOMAIN set (closes: #1849)
- chore: allow specifying client assertion config via env vars

## [v4.0.0-beta.12](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.12) (2024-12-18)

**Fixed**

- chore: add note about RP-Initiated logout
- chore: warn instead of throwing error when using insecure requests flag in prod (closes: #1846)
- chore: remove warning for prod env with non-https (closes: #1847)

## [v4.0.0-beta.11](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.11) (2024-12-17)

- feat: introduce updateSession helper (closes: #1836)
- feat: private_key_jwt authentication method
- fix: peerDependencies for React 19 (closes: #1844)
- chore: allowInsecureRequests for mock OIDC server during development (closes: #1846)

## [v4.0.0-beta.10](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.10) (2024-12-10)

**Fixed**

- chore: add more description in error log on discovery errors (closes: #1832)
- chore: migration guide
- chore: include typeVersions for type resolution (fixes: #1816)
- fix: only dist files should be published (fixes: #1825)
- feat: add PAR support
- feat: allow customizing auth routes (closes: #1834)
- chore: set secure cookie attribute based on app base URL protocol (closes: #1821)

## [v4.0.0-beta.9](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.9) (2024-12-03)

**Fixed**

- fix: clear session before redirecting to /v2/logout (closes #1826)
- feature: add Auth0Provider to pass initialUser (closes: #1823)
- fix: getAccessToken types should not return null (closes: #1831)

## [v4.0.0-beta.8](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.8) (2024-11-25)

**Fixed**

- Fixes documentation for allowed logout URL
- Falls back to /v2/logout endpoint when the end_session_endpoint is not enabled for a tenant
- Adds docs about default claims from ID token populated in the user object
- Prevent revalidation when user is not authenticated in useUser() hook
- Fix error handling in useUser() hook (closes #1817)
- Export types under /types sub-module (closes #1824 and #1810)
- Exports errors under /errors sub-module
- getAccessToken() method throws an error when an access token could not be obtained to allow handling by the caller (closes #1820 and #1819)
- Add warning when cookie size exceeds 4096 bytes

## [v4.0.0-beta.7](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.7) (2024-11-19)

**Fixed**

- Updated README.md
- Bumped up the version

## [v4.0.0-beta.5](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.5) (2024-11-19)

**Fixed**

- Bumping up the version

## [v4.0.0-beta.4](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.4) (2024-11-19)

**Fixed**

- Adds e2e tests.
- Removes error on env vars when undefined during build.

## [v4.0.0-beta.3](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.3) (2024-11-14)

**Fixed**

- Bug fixes
- Addressing the following customer issues.
  - #1797
  - #1795
  - #1794

## [v4.0.0-beta.2](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.2) (2024-11-11)

- The previous NPM publish missed including the build files. We are now bumping the version and releasing an updated version with the latest build.

## [v4.0.0-beta.1](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.1) (2024-11-11)

**Fixed**

- ESM imports for Pages router

## [v4.0.0-beta.0](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-beta.0) (2024-11-05)

- Expands unit test coverage
- Implements Back-Channel Logout
- Adds sample with shadcn
- Refer [README.md](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file) for more details.

## [v4.0.0-alpha.0](https://github.com/auth0/nextjs-auth0/releases/tag/v4.0.0-alpha.0) (2024-10-23)

- This is an experimental alpha release, and we encourage users to test it thoroughly in their development environments before upgrading in production.
- Review the breaking changes carefully to ensure a smooth transition.
- Refer [README.md](https://github.com/auth0/nextjs-auth0/tree/v4?tab=readme-ov-file) for more details.

## [v3.5.0](https://github.com/auth0/nextjs-auth0/tree/v3.5.0) (2023-12-06)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.4.0...v3.5.0)

**Added**

- Add Pushed Authorization Requests [\#1598](https://github.com/auth0/nextjs-auth0/pull/1598) ([ewanharris](https://github.com/ewanharris))

## [v3.4.0](https://github.com/auth0/nextjs-auth0/tree/v3.4.0) (2023-12-04)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.3.0...v3.4.0)

**Added**

- [SDK-4719] Back-Channel Logout [\#1590](https://github.com/auth0/nextjs-auth0/pull/1590) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Should get instance of Session in RSCs [\#1565](https://github.com/auth0/nextjs-auth0/pull/1565) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.3.0](https://github.com/auth0/nextjs-auth0/tree/v3.3.0) (2023-11-13)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.2.0...v3.3.0)

**Added**

- Bail out of static rendering for pages and routes in app dir [\#1541](https://github.com/auth0/nextjs-auth0/pull/1541) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Fix wrong response type in AfterRefreshPageRoute [\#1523](https://github.com/auth0/nextjs-auth0/pull/1523) ([thutter](https://github.com/thutter))

## [v3.2.0](https://github.com/auth0/nextjs-auth0/tree/v3.2.0) (2023-10-05)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.1.0...v3.2.0)

**Added**

- Add support for passing a custom http agent [\#1447](https://github.com/auth0/nextjs-auth0/pull/1447) ([ryanolson-aumni](https://github.com/ryanolson-aumni))
- fix: add missing touchSession for exported function [\#1461](https://github.com/auth0/nextjs-auth0/pull/1461) ([benevbright](https://github.com/benevbright))

**Fixed**

- withApiAuthRequired callback can return just Response [\#1476](https://github.com/auth0/nextjs-auth0/pull/1476) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.1.0](https://github.com/auth0/nextjs-auth0/tree/v3.1.0) (2023-08-08)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.0.1...v3.1.0)

**Added**

- Add option to override transaction cookie name and config [\#1346](https://github.com/auth0/nextjs-auth0/pull/1346) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add support for customizing returnTo in middleware [\#1342](https://github.com/auth0/nextjs-auth0/pull/1342) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Changed**

- Move state cookies to under a single cookie [\#1343](https://github.com/auth0/nextjs-auth0/pull/1343) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- Fix for edge cookies delete not supporting domain or path [\#1341](https://github.com/auth0/nextjs-auth0/pull/1341) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.1](https://github.com/auth0/nextjs-auth0/tree/v3.0.1) (2023-07-31)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.0.0...v3.0.1)

**Fixed**

- Fix auth handler types when using custom handlers [\#1327](https://github.com/auth0/nextjs-auth0/pull/1327) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.0](https://github.com/auth0/nextjs-auth0/tree/v3.0.0) (2023-07-25)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.7.0...v3.0.0)

**Added**

- Support for the App Router
- Support for Edge Runtime
- Support for Responses in Middleware

**⚠️ BREAKING CHANGES**

- Support for EOL Node versions 12 and 14 has been removed. See the [V3_MIGRATION_GUIDE.md](./V3_MIGRATION_GUIDE.md) for more details.

## [v2.7.0](https://github.com/auth0/nextjs-auth0/tree/v2.7.0) (2023-07-19)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.6.3...v2.7.0)

**Added**

- Support Organization Name [\#1291](https://github.com/auth0/nextjs-auth0/pull/1291) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**

- Clean up erroneous cookies when chunk size decreases [\#1300](https://github.com/auth0/nextjs-auth0/pull/1300) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.0-beta.3](https://github.com/auth0/nextjs-auth0/tree/v3.0.0-beta.3) (2023-06-28)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.0.0-beta.2...v3.0.0-beta.3)

**Added**

- [SDK-4319] Add support for Edge runtime [\#1269](https://github.com/auth0/nextjs-auth0/pull/1269) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-4318] Enable responses from custom middleware [\#1265](https://github.com/auth0/nextjs-auth0/pull/1265) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.6.3](https://github.com/auth0/nextjs-auth0/tree/v2.6.3) (2023-06-26)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.6.2...v2.6.3)

**Fixed**

- Fix for setting custom cookies in `withMiddlewareAuthRequired` [\#1263](https://github.com/auth0/nextjs-auth0/pull/1263) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.0-beta.2](https://github.com/auth0/nextjs-auth0/tree/v3.0.0-beta.2) (2023-06-16)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.0.0-beta.1...v3.0.0-beta.2)

**Fixed**

- Fix issue where api wrapper was overwriting session update in api [\#1255](https://github.com/auth0/nextjs-auth0/pull/1255) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.0-beta.1](https://github.com/auth0/nextjs-auth0/tree/v3.0.0-beta.1) (2023-06-13)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v3.0.0-beta.0...v3.0.0-beta.1)

**Fixed**

- Fix request check in node 16 [\#1250](https://github.com/auth0/nextjs-auth0/pull/1250) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.6.2](https://github.com/auth0/nextjs-auth0/tree/v2.6.2) (2023-06-09)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.6.1...v2.6.2)

**Fixed**

- Fix for handling chunked cookies in edge runtime [\#1236](https://github.com/auth0/nextjs-auth0/pull/1236) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v3.0.0-beta.0](https://github.com/auth0/nextjs-auth0/tree/v3.0.0-beta.0) (2023-06-08)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.6.1...v3.0.0-beta.0)

**Added**

- Support for the App Router.

**⚠️ BREAKING CHANGES**

- Support for EOL Node versions 12 and 14 has been removed. See the [V3_MIGRATION_GUIDE.md](./V3_MIGRATION_GUIDE.md) for more details.

## [v2.6.1](https://github.com/auth0/nextjs-auth0/tree/v2.6.1) (2023-06-06)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.6.0...v2.6.1)

**Fixed**

- [SDK-4113] Lock down open ended auth route [\#1212](https://github.com/auth0/nextjs-auth0/pull/1212) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.6.0](https://github.com/auth0/nextjs-auth0/tree/v2.6.0) (2023-05-12)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.5.0...v2.6.0)

**Added**

- Add prefixed url env for preview deploys on middleware [\#1198](https://github.com/auth0/nextjs-auth0/pull/1198) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.5.0](https://github.com/auth0/nextjs-auth0/tree/v2.5.0) (2023-04-18)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.4.0...v2.5.0)

**Added**

- feat: add optional session param to genId function [\#1158](https://github.com/auth0/nextjs-auth0/pull/1158) ([PSoltes](https://github.com/PSoltes))

## [v2.4.0](https://github.com/auth0/nextjs-auth0/tree/v2.4.0) (2023-03-27)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.3.1...v2.4.0)

**Added**

- Add `autoSave`/`touchSession` for rolling session expiry management [\#1116](https://github.com/auth0/nextjs-auth0/pull/1116) ([aovens-quantifi](https://github.com/aovens-quantifi))

## [v2.3.1](https://github.com/auth0/nextjs-auth0/tree/v2.3.1) (2023-03-17)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.3.0...v2.3.1)

**Fixed**

- Update stateful session cookie expiry on set [\#1115](https://github.com/auth0/nextjs-auth0/pull/1115) ([aovens-quantifi](https://github.com/aovens-quantifi))

## [v2.3.0](https://github.com/auth0/nextjs-auth0/tree/v2.3.0) (2023-03-16)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.2.3...v2.3.0)

**Added**

- Add AUTH0_LOGOUT env var [\#1113](https://github.com/auth0/nextjs-auth0/pull/1113) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.2.3](https://github.com/auth0/nextjs-auth0/tree/v2.2.3) (2023-03-13)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.2.2...v2.2.3)

**Fixed**

- [SDK-3887] Always honor auth0Logout config [\#1104](https://github.com/auth0/nextjs-auth0/pull/1104) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.2.2](https://github.com/auth0/nextjs-auth0/tree/v2.2.2) (2023-03-02)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.2.1...v2.2.2)

**Fixed**

- Fix issue where storeIDToken config not used by getAccessToken [\#1091](https://github.com/auth0/nextjs-auth0/pull/1091) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.2.1](https://github.com/auth0/nextjs-auth0/tree/v2.2.1) (2023-01-27)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.2.0...v2.2.1)

**Fixed**

- Remove type from export in d.ts files [\#1037](https://github.com/auth0/nextjs-auth0/pull/1037) ([ewanharris](https://github.com/ewanharris))

## [v2.2.0](https://github.com/auth0/nextjs-auth0/tree/v2.2.0) (2023-01-24)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.1.0...v2.2.0)

**Added**

- [SDK-3862] Add support for JWT client authentication [\#1029](https://github.com/auth0/nextjs-auth0/pull/1029) ([ewanharris](https://github.com/ewanharris))

**Fixed**

- withMiddlewareAuthRequired returnTo should be a relative url [\#1028](https://github.com/auth0/nextjs-auth0/pull/1028) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Infer user exists if WithPageAuthRequired page is rendered [\#1014](https://github.com/auth0/nextjs-auth0/pull/1014) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.1.0](https://github.com/auth0/nextjs-auth0/tree/v2.1.0) (2023-01-11)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.1...v2.1.0)

**Added**

- SDK-3807 Add custom session stores [\#993](https://github.com/auth0/nextjs-auth0/pull/993) ([adamjmcgrath](https://github.com/adamjmcgrath))

## [v2.0.1](https://github.com/auth0/nextjs-auth0/tree/v2.0.1) (2022-12-09)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.0...v2.0.1)

**Fixed**

- afterCallback return type fix [\#954](https://github.com/auth0/nextjs-auth0/pull/954) ([alexmalev](https://github.com/alexmalev))
- fix/rerenders: useMemo to avoid unnecessary rerenders [\#945](https://github.com/auth0/nextjs-auth0/pull/945) ([stavros-liaskos](https://github.com/stavros-liaskos))

## [v2.0.0](https://github.com/auth0/nextjs-auth0/tree/v2.0.0) (2022-12-01)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v1.9.2...v2.0.0)

**⚠️ BREAKING CHANGES**

- Refactor session lifecycle [\#787](https://github.com/auth0/nextjs-auth0/pull/787) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Rearrange exports for RSC and add experimental RSC route to example [\#913](https://github.com/auth0/nextjs-auth0/pull/913) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Improved callback errors [\#835](https://github.com/auth0/nextjs-auth0/pull/835) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Prevent mixing named exports and own instances [\#825](https://github.com/auth0/nextjs-auth0/pull/825) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Allow to override the user prop in server-side rendered pages [\#800](https://github.com/auth0/nextjs-auth0/pull/800) ([Widcket](https://github.com/Widcket))
- Return 204 from /api/auth/me when logged out [\#791](https://github.com/auth0/nextjs-auth0/pull/791) ([Widcket](https://github.com/Widcket))

  **Added**

- Next.js Middlware support [\#815](https://github.com/auth0/nextjs-auth0/pull/815) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add testing utility for generating session cookies [\#816](https://github.com/auth0/nextjs-auth0/pull/816) ([Widcket](https://github.com/Widcket))
- Add updateUser [\#855](https://github.com/auth0/nextjs-auth0/pull/855) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add support for configuring the built-in handlers [\#826](https://github.com/auth0/nextjs-auth0/pull/826) ([Widcket](https://github.com/Widcket))
- Add support for configuring the default handlers [\#840](https://github.com/auth0/nextjs-auth0/pull/840) ([Widcket](https://github.com/Widcket))
- Add logout options [\#877](https://github.com/auth0/nextjs-auth0/pull/877) ([adamjmcgrath](https://github.com/adamjmcgrath))
- At error cause to AT error when it's from a failed grant [\#878](https://github.com/auth0/nextjs-auth0/pull/878) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Add option to not store ID Token in session [\#809](https://github.com/auth0/nextjs-auth0/pull/809) ([Widcket](https://github.com/Widcket))
- Default error handler [\#823](https://github.com/auth0/nextjs-auth0/pull/823) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Allow response customization in afterCallback [\#838](https://github.com/auth0/nextjs-auth0/pull/838) ([adamjmcgrath](https://github.com/adamjmcgrath))
- Improve API docs [\#796](https://github.com/auth0/nextjs-auth0/pull/796) ([Widcket](https://github.com/Widcket))
- Improve errors [\#782](https://github.com/auth0/nextjs-auth0/pull/782) ([Widcket](https://github.com/Widcket))

See [V2 Migration Guide](./V2_MIGRATION_GUIDE.md) for full details.

## [v2.0.0-beta.4](https://github.com/auth0/nextjs-auth0/tree/v2.0.0-beta.4) (2022-11-18)

[Full Changelog](https://github.com/auth0/nextjs-auth0/compare/v2.0.0-beta.3...v2.0.0-beta.4)

**⚠️ BREAKING CHANGES**

- Rearrange exports for RSC and add experimental RSC route to example [\#913](https://github.com/auth0/nextjs-auth0/pull/913) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**

- WithMiddlewareAuthRequired should return 401 for /api routes [\#909](https://github.com/auth0/nextjs-auth0/pull/909) ([adamjmcgrath](https://github.com/adamjmcgrath))

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
