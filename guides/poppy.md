# Poppy (Personal Agents)

Examples for letting personal AI agents, such as Meta Muse, shop and manage accounts on your Next.js site through the Auth0 Next.js SDK, using the Poppy (Personal Agent Protocol).

> **Beta.** Poppy support may change without a major release. Poppy is in beta on Auth0, so your tenant needs it enabled. The SDK isn't tied to one protocol version: it serves your `poppy.json` as written.

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [How it works](#how-it-works)
- [Setup](#setup)
  - [1. Configure Auth0](#1-configure-auth0)
  - [2. Add `poppy.json`](#2-add-poppyjson)
  - [3. Turn it on](#3-turn-it-on)
- [The discovery files](#the-discovery-files)
- [Knowing who is driving](#knowing-who-is-driving)
  - [Client-side usage](#client-side-usage)
- [Guests and signed-in agents](#guests-and-signed-in-agents)
- [Logging out](#logging-out)
- [Error handling](#error-handling)
- [Testing locally](#testing-locally)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## How it works

An agent reaches your site in two ways. It can call your APIs with a signed `Poppy-Session` header, which `@auth0/auth0-api-js` handles. Or it can drive a browser on your website, which is what the SDK handles and this guide covers.

1. The agent reads `/.well-known/poppy.json` and `/.well-known/oauth-protected-resource` on your domain. **The SDK serves both.**
2. The agent's browser opens an Auth0-hosted *join* page, and the agent's backend proves who it is to Auth0. **Auth0 verifies the agent. The SDK never sees that proof.**
3. Auth0 sends the browser to your `/auth/login`, then back to `/auth/callback`, and the SDK exchanges the code as for any login. **The SDK reads the agent from the ID token Auth0 signed.**
4. Your code asks `auth0.poppy.getContext()` who is driving.

Auth0's join currently sends no query parameters, so after a join the browser lands on your default page. A join that sends `iss` and `target_link_uri` (OIDC third-party-initiated login) is also handled: the browser lands on `target_link_uri` when `iss` matches your issuer and the target is on your origin, and a different `iss` is refused with `400`.

An agent is either a **guest** (the customer hasn't approved it yet) or **signed in** (it acts in the customer's account).

## Setup

### 1. Configure Auth0

Poppy is in beta on Auth0, so ask Auth0 to enable it for your tenant. Then run:

```sh
auth0 poppy setup --company-domain <your-domain>
```

It turns on the browser join for your web app, sets the page where a join starts a sign-in to `https://<your-site>/auth/login` (it must be HTTPS), and writes `poppy.json`. Register the agents you allow with `auth0 agents register`.

Setup also offers to add an Action that issues refresh tokens to agents. It covers only the agent's own sign-in to your API: a browser join never gives your website a refresh token.

### 2. Add `poppy.json`

`auth0 poppy setup` writes the file. To create it again from the tenant, run `auth0 poppy config`, and check it:

```sh
auth0 poppy config --company-domain fernway.com --out ./poppy.json
auth0 poppy doctor fernway.com --config ./poppy.json
```

`poppy.json` is your discovery document, and it holds no secrets, so it's safe to commit. The SDK serves it as written at `/.well-known/poppy.json`, so the whole file is public: don't add anything private to it. It reads only two values from it:

| Field | Used for |
| --- | --- |
| `organization.domain` | The protected resource, `https://<domain>`. A bare host, with a port only when it isn't 443 |
| `auth.issuer` | The authorization server, and checking a browser join's `iss`. **Exactly as Auth0 publishes it, including the trailing slash** |

The SDK checks only these two at startup. `auth0 poppy doctor` checks the rest of the file.

**Set `web.unscoped` to `true` unless your app limits the agent to its scopes.** A signed-in agent gets a normal `getSession()`, so by default your website gives it everything the account can do, and the protocol requires `web.unscoped: true` in that case. If your app instead checks the agent's `scopes` from `getContext()` before each action, leave it out. To get those scopes, add your API's scopes to `authorizationParameters.scope`: Auth0 grants only the ones the customer approved for the agent.

### 3. Turn it on

```ts
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";
import poppyConfig from "../poppy.json"; // needs "resolveJsonModule": true

export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig }
});
```

The config is passed as an object, not a path, so it also works in Edge middleware. An invalid `organization.domain` or `auth.issuer` throws `InvalidConfigurationError` when the client is created, with the fix in the message. For example: `auth.issuer must match Auth0's issuer exactly, including the trailing slash`.

Agents fetch the files at the host root, so if your app has a `basePath`, serve them at the root another way; the SDK warns at startup. Your middleware matcher has to let `/.well-known/*` through to the SDK:

```ts
// middleware.ts (or proxy.ts)
import type { NextRequest } from "next/server";
import { auth0 } from "./lib/auth0";

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"]
};
```

That's all that's required. Without the `poppy` option, nothing changes.

## The discovery files

The SDK serves both on `GET`, built once at startup from `poppy.json` and never from the request's `Host` header. `poppy.json` is served as written; `oauth-protected-resource` comes from `organization.domain` and `auth.issuer`:

```jsonc
// GET /.well-known/poppy.json
{
  "protocol_version": "<major.minor>",
  "organization": { "name": "Fernway", "domain": "fernway.com" },
  "auth": { "issuer": "https://auth.fernway.com/", "scopes": { "orders:write": "Place orders" } },
  "web": { "browser_session_endpoint": "https://auth.fernway.com/poppy/<web-app-client-id>/browser-session" }
}

// GET /.well-known/oauth-protected-resource
{ "resource": "https://fernway.com", "authorization_servers": ["https://auth.fernway.com/"] }
```

Agents compare these with Auth0's own metadata character for character, and skip your site without saying why if anything differs.

## Knowing who is driving

`auth0.poppy.getContext()` mirrors `getSession()`: no argument in the App Router, and `req` in middleware and the Pages Router.

```ts
type PoppyContext =
  | { kind: "human" }
  | {
      kind: "agent";
      state: "guest" | "signed_in";
      // The ID token's own claims:
      sub: string;                   // the customer's Auth0 user ID once signed in, or anon_poppy@… for a guest
      sub_profile?: string;          // only on a guest: "user urn:auth0:anonymous_user"; a signed-in join has none
      act: {                         // the ID token's act, as Auth0 sent it: the agent acting
        sub: string;                 // the agent: its Auth0 agent ID, or its client metadata URL
        poppy_sid: string;           // Poppy Session ID, from this join
        poppy_user_id: string;       // the agent's pairwise ID for this person
        poppy_agent_id?: string;     // which of the agent's agents, when it sent one
        client_id?: string;          // the agent's Auth0 client ID
        sub_profile?: string;        // for example "ai_agent"
        iss?: string;
        [claim: string]: unknown;    // any other act claim
      };
      scopes: string[];              // the website token's scopes; [] for a guest
    };
```

It mirrors the ID token Auth0 issued for the join, so there are two `sub` values: the token's own `sub` (outside `act`) and the agent's `act.sub`.

For a signed-in agent, Auth0 grants the website no more than the customer approved for the agent, plus OpenID scopes such as `openid` and `profile`. `scopes` can be fewer than the agent's, never more.

`act` keeps its token names. `act.sub` is the agent, and `act.poppy_user_id` is the agent's pairwise ID for the person. The customer's Auth0 user ID is the context's own `sub`, which is the same as `session.user.sub` once signed in.

**Server Component: show a banner to agents**

```tsx
const poppy = await auth0.poppy.getContext();
if (poppy.kind === "agent") {
  return <Banner>Browsing via {poppy.act.sub} ({poppy.state})</Banner>;
}
```

**Cart keyed by the Poppy Session**

```ts
const poppy = await auth0.poppy.getContext();
const cartKey =
  poppy.kind === "agent"
    ? `${poppy.act.sub}|${poppy.act.poppy_sid}`
    : (await auth0.getSession())?.user.sub;
```

This key stays the same from guest to signed in only when the agent signs in within the same Poppy Session and its link in Auth0 doesn't change: Auth0 takes `poppy_sid` from each join and `act.sub` from the agent's link at the time. Otherwise the signed-in agent gets another key, so move the guest's cart when the agent signs in if you need to keep it.

**Server Action: set your own rules for agents**

```ts
"use server";
export async function placeOrder(cart: Cart) {
  const poppy = await auth0.poppy.getContext();
  if (poppy.kind === "agent") {
    if (poppy.state === "guest") throw new Error("Sign in through your agent to order");
    await saveOrder(cart, { placedVia: poppy.act.sub });
    return;
  }
  await saveOrder(cart);
}
```

**Middleware and the Pages Router**

```ts
const poppy = await auth0.poppy.getContext(req);
```

`getContext()` always returns `{ kind: "human" }` when the `poppy` option isn't set. A guest and a session are never in the browser together: see [Guests and signed-in agents](#guests-and-signed-in-agents).

The SDK keeps no storage of its own for Poppy Sessions. Where you keep carts and how you link a guest to a customer is up to your app, and `act.poppy_sid` is the key to use.

### Client-side usage

Prefer reading the context in a Server Component and passing what the page needs to client components as props. When only client code has what it needs, use `poppy.getContext()`, which calls the SDK's `/auth/poppy-context` route:

```tsx
"use client";
import { poppy } from "@auth0/nextjs-auth0";
import { PoppyErrorCode } from "@auth0/nextjs-auth0/errors";

try {
  const context = await poppy.getContext(); // the same value as auth0.poppy.getContext()
  if (context.kind === "agent") showAgentBanner(context.state);
} catch (error) {
  if (error.code === PoppyErrorCode.NOT_ENABLED) {
    // the route answered 404: the poppy option isn't set
  }
}
```

The route answers `GET` only, is never cached, returns `404` when the `poppy` option isn't set, and `401` when the session can't be read. It returns no tokens, but the token's `sub` and `sub_profile` and every `act` claim, such as `poppy_sid`, `poppy_user_id`, `client_id` and `iss`, become readable by every script on the page, including analytics and other third-party scripts, so only call it on pages that need it.

To change the path, set `NEXT_PUBLIC_POPPY_CONTEXT_ROUTE`, which both the server and `poppy.getContext()` read. If you set `routes.poppyContext` instead, set the variable to the same path.

There is no hook: `useUser()` stays `null` for a guest, because a guest is not a signed-in user.

## Guests and signed-in agents

| | Agent guest (signed out) | Signed-in agent |
| --- | --- | --- |
| Stored in | The anonymous session cookie (`auth0_anon`). `anonymousSession` doesn't need to be enabled | The normal session cookie |
| `getSession()` | **`null`**, so code that only checks "logged in" never treats a guest as a customer | The customer's session |
| `getAnonymousSession()` | The guest: `{ id, accessToken, expiresAt }` | `null` |
| Lifetime | Until the join's ID token expires (Auth0 caps it at 2 hours). Its access token can expire sooner: `getAnonymousSession()` is then `null` until a silent login renews it | Until the join's ID token expires. Rolling can't extend it past that |
| `onCallback`, `beforeSessionSaved` | **Not called**: both receive a user session, so a hook written for people could treat the guest as a customer | Called as usual |
| Agent state | Inside the guest cookie | In `session.internal.poppy`. `beforeSessionSaved` and `updateSession` can't remove it |

When the customer approves the agent and it joins again, the SDK replaces the guest with the customer's session and deletes the guest cookie, even if `clearAnonymousSessionOnLogin` is `false`.

**A guest and a session are never in the browser together.** Auth0 refuses a guest join in a browser signed in to an account: it shows a `session_conflict` error page on its own domain, so the join never reaches your site. A guest join over an earlier guest replaces it. If a guest join still finds a session in your app, for example because your app's session outlived the Auth0 session, the SDK ends that session, a person's or a signed-in agent's, so the agent never acts with an account it wasn't approved for. The Poppy spec says a join SHOULD keep the browser's own login; the SDK ends it for that reason.

**Only a signed-in agent join can replace a guest.** While a guest is in the browser, a login replaces it only if it's a signed-in agent join (a login whose ID token has a Poppy agent `act`), or a new guest join (another guest `sub` or Poppy Session). The SDK doesn't compare the agent join with the guest, since the agent's `act.sub`, `poppy_user_id` and `poppy_sid` can differ between the two joins. Any other login is refused with `poppy_sign_in_required`: a person's login, by the usual redirect, a popup, a passkey or passwordless, and the same guest coming back while its access token is valid. That last one matters: on Auth0 a guest's own login comes back as the same guest, so a page that sends a guest to log in would otherwise loop. The SDK refuses after one round trip. Once the guest's access token has expired, the same guest coming back is accepted once, to renew the token. The callback passes the error to `onCallback`, whose default answers `500` with the error message; logging out ends the guest, and the person can then sign in. The passkey and passwordless routes answer `403` JSON, and `auth0.passkey.*` and `auth0.passwordless.*` throw the `PoppyError`. A guest that has already ended doesn't block anything.

**A guest join replaces an anonymous session.** The guest is stored in the anonymous session cookie, so it replaces any anonymous session already in that browser. An agent's browser shouldn't have one: the agent joins only a browser it controls.

**`beforeSessionSaved` and claims.** Without the hook, the SDK keeps the default ID token claims plus `sub_profile` and `client_profile` for a signed-in agent. Setting the hook turns that filtering off for every login, and your hook receives every claim. To keep the same claims:

```ts
import { filterDefaultIdTokenClaims } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig },
  async beforeSessionSaved(session) {
    const { sub_profile, client_profile } = session.user;
    return {
      ...session,
      user: {
        ...filterDefaultIdTokenClaims(session.user),
        ...(sub_profile !== undefined && { sub_profile }),
        ...(client_profile !== undefined && { client_profile })
      }
    };
  }
});
```

The agent state is kept outside `session.user`, so the hook can't remove it either way.

## Logging out

`/auth/logout` also ends a Poppy guest: the SDK deletes the guest cookie and sends the browser to Auth0's logout. A guest's logout always goes to `/v2/logout`, whatever `logoutStrategy` says, because a guest has no ID token or session ID for OIDC logout. Every other logout, a person's or a signed-in agent's, uses `logoutStrategy` as usual. `returnTo` must be in your application's Allowed Logout URLs. A guest that has already expired is logged out the same way.

## Error handling

A login that looks like a guest (an `anon_poppy@` subject or Auth0's anonymous `sub_profile`) but isn't a valid Poppy guest is refused, and nothing is stored. The error is a `PoppyError`, so check `error.code`. `error.reason` names the failing check, and the SDK logs it on the server. It's kept out of the message, because the default `onCallback` returns the message to the browser. The reason lists claim names but no claim values, apart from the `sub_profile` label.

```ts
import { NextResponse } from "next/server";
import { PoppyErrorCode } from "@auth0/nextjs-auth0/errors";

export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig },
  onCallback: async (error, context) => {
    if (error?.code === PoppyErrorCode.INVALID_GUEST) {
      console.error("Poppy login refused:", error.reason);
      return new NextResponse("Sign-in failed.", { status: 500 });
    }
    // ...
  }
});
```

| Where | Code | When |
| --- | --- | --- |
| `new Auth0Client()` | `invalid_configuration` (`InvalidConfigurationError`) | `poppy.config` is invalid |
| Callback | `invalid_poppy_guest` (`PoppyError`) | A guest-looking login that isn't a valid Poppy guest |
| Callback, popup, passkey and passwordless routes | `invalid_poppy_agent` (`PoppyError`) | A login with a Poppy agent `act` but no valid `sub` or `exp`. It is refused rather than taken as a person |
| Popup callback (`postMessage` error), passkey and passwordless routes (403 JSON) | `poppy_guest_not_supported` (`PoppyError`) | A guest login outside the browser join's redirect callback |
| Callback (`onCallback`), popup (`postMessage` error), passkey and passwordless routes (403 JSON) | `poppy_sign_in_required` (`PoppyError`) | A login over an active guest that isn't a signed-in agent join or a new guest join |
| Callback | `session_expired` (`AccessTokenError`) | The join's tokens were about to expire on arrival |
| `poppy.getContext()` (client) | `poppy_not_enabled` (`PoppyError`) | The context route answered 404: the `poppy` option isn't set |
| `poppy.getContext()` (client) | `poppy_context_unavailable` (`PoppyError`) | The context route failed or couldn't be reached |

## Testing locally

Agents only accept your site on a public HTTPS host, but you can check the files on `next dev`:

- Outside production, a loopback `domain` (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`) may include a port, for example `"domain": "localhost:3000"`. The protected resource then uses `http`, and the SDK logs a warning.
- In production a loopback `domain` throws, **including at `next build`**, so set `domain` to your public host before building.

```bash
curl http://localhost:3000/.well-known/poppy.json
curl http://localhost:3000/.well-known/oauth-protected-resource
```

To run a real agent join, you need a tenant with Poppy enabled, an agent registered on it, and your site on a public HTTPS host such as a tunnel or a reverse proxy.

## Limitations

- **No refresh token.** Auth0 issues no refresh token for a join, by design: the website's session must not outlive what the agent was allowed, at most 2 hours. For a signed-in agent, `getAccessToken()` can't refresh the token or get one for another audience; when the session ends, the agent joins again. A login for an API the customer didn't approve for the agent fails with an authorization error.
- **Silent login for a guest.** While the guest's token is valid, a silent login (`prompt=none`) is refused with `poppy_sign_in_required`, so a page can't loop. Once the token has expired, the SDK accepts the same guest and stores the new token, but keeps the first join's deadline: Auth0's guest session lasts 2 hours from the join, and a renewal doesn't extend it. Auth0 returns the guest only while that session is live; after it, a silent login answers `login_required` and a normal one shows Auth0's login page. Don't run silent logins for a guest: check `poppy.getContext()` first.
- **Disconnecting.** Only revoking the agent's refresh token ends the browser's sign-in early. Removing a grant or blocking the user doesn't. Tokens from the join last at most 2 hours.
- **`protected_resources`.** Agents check that Auth0's metadata lists your domain there. Until Auth0 publishes it, agents may not trust your site.
- **Other apps on the tenant.** Auth0 doesn't limit a guest's session to the app that created it: another first-party app on the tenant with browser join enabled can sign in to it as the same `anon_poppy@…` user. An app without the `poppy` option would take that user for a customer.
- **Back-channel logout.** It doesn't reach guests, which live only in the browser's guest cookie.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `/.well-known/*` returns 404 | The `poppy` option isn't set, or the middleware matcher excludes `/.well-known/*` |
| A startup warning about `basePath`, or agents can't find the files | Agents fetch `/.well-known/*` at the host root, which an app with a `basePath` never receives. Serve the files at the root another way, such as a rewrite or a proxy |
| 500 at startup with `Invalid poppy.config: …` | The config is invalid. The message names the fix |
| Agents ignore the site | `issuer` doesn't match Auth0's character for character, or the site isn't on a public HTTPS host |
| `/auth/login` fails with "An error occurred while trying to initiate the login request." | The server can't reach your tenant. Check the server log for the underlying error |
| Log in, or a protected page, ends on "An agent guest is driving this browser…" | A guest is in the browser, and only a signed-in agent join can replace it. Log out (`/auth/logout`) to end the guest, then log in. On Auth0 the guest's own login comes back as the same guest, which the SDK stops instead of looping |
| A signed-in agent's login fails with `access_denied`: "The requested audience is not authorized for this session." | The login's `audience` doesn't match the API the customer approved for the agent. Set `authorizationParameters.audience` to that API's identifier |
| The callback fails with `invalid_poppy_guest` or `invalid_poppy_agent` | Read the server log, or `error.reason` in your `onCallback`. It names the failing check |
| The agent lands on your home page after a join, not the page it asked for | Expected today: Auth0's join sends no `target_link_uri`. When a join sends one, it is used only with a matching `iss` |
| `/auth/login` answers `400` with "Invalid iss query param" | The join's `iss` isn't your `auth.issuer` or your tenant's issuer. Check `auth.issuer` in `poppy.json` |
| `poppy.getContext()` throws `poppy_not_enabled` | The `poppy` option isn't set, or `routes.poppyContext` is set to a path other than `NEXT_PUBLIC_POPPY_CONTEXT_ROUTE` |
| A signed-in agent's join fails at the callback | Auth0 needed to show a prompt, such as MFA, which an agent can't complete. Skip the prompt for these logins, for example in an Action |
| A guest isn't kept in the browser | The guest cookie is `Secure` by default, so serve the site over HTTPS |
