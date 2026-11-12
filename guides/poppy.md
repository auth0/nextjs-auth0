# Poppy (Personal Agents)

Examples for letting personal AI agents, such as Meta Muse, shop and manage accounts on your Next.js site through the Auth0 Next.js SDK, using the Poppy (Personal Agent Protocol).

> **Beta.** Poppy support may change without a major release. Poppy is in beta on Auth0, so your tenant needs it enabled. The SDK isn't tied to one protocol version: it serves the version your `auth0-poppy.json` names.

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [How it works](#how-it-works)
- [Setup](#setup)
  - [1. Configure Auth0](#1-configure-auth0)
  - [2. Add `auth0-poppy.json`](#2-add-auth0-poppyjson)
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
3. Auth0 sends the browser to your `/auth/login` with `iss` and `target_link_uri`, then back to `/auth/callback`, and the SDK exchanges the code as for any login. **The SDK reads the agent from the ID token Auth0 signed.**
4. Your code asks `auth0.poppy.getContext()` who is driving.

The SDK treats a login as the agent's join only when `iss` matches your issuer. Without it, `target_link_uri` is ignored and the browser lands on your default page.

An agent is either a **guest** (the customer hasn't approved it yet) or **signed in** (it acts in the customer's account).

## Setup

### 1. Configure Auth0

Until `auth0 poppy setup` is available, ask Auth0 to enable Poppy for your tenant, then:

- Set your web application's **Initiate Login URI** to `https://<your-site>/auth/login`. It must be HTTPS.
- Register the agents you allow.

### 2. Add `auth0-poppy.json`

The file holds no secrets, so it's safe to commit:

```json
{
  "protocolVersion": "0.4",
  "domain": "fernway.com",
  "issuer": "https://auth.fernway.com/",
  "browserSessionEndpoint": "https://auth.fernway.com/poppy/<web-app-client-id>/browser-session",
  "organizationName": "Fernway",
  "scopes": {
    "orders:write": "Place orders",
    "returns:write": "Start a return"
  }
}
```

| Field | Meaning |
| --- | --- |
| `protocolVersion` | The Poppy version your tenant implements, as `major.minor`. Served as `protocol_version` unchanged |
| `domain` | The host that serves the files: no scheme, port or path |
| `issuer` | Your Auth0 issuer, **exactly as Auth0 publishes it, including the trailing slash** |
| `browserSessionEndpoint` | The Auth0-hosted join URL for your web app |
| `scopes` | Optional. Each scope an agent can ask for, with a description |
| `organizationName`, `logoUri` | Optional. Shown to the customer |

### 3. Turn it on

```ts
// lib/auth0.ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";
import poppyConfig from "../auth0-poppy.json"; // needs "resolveJsonModule": true

export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig }
});
```

The config is passed as an object, not a path, so it also works in Edge middleware. An invalid config throws `InvalidConfigurationError` when the client is created, with the fix in the message. For example: `issuer must match Auth0's issuer exactly, including the trailing slash`.

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

The SDK serves both on `GET`, built once at startup from the config and never from the request's `Host` header:

```jsonc
// GET /.well-known/poppy.json
{
  "protocol_version": "0.4",
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
      sub_profile?: string;          // "user", or "user urn:auth0:anonymous_user" for a guest
      act: {                         // the ID token's act, as Auth0 sent it: the agent acting
        sub: string;                 // the agent: its Auth0 agent ID, or its client metadata URL
        poppy_sid: string;           // Poppy Session ID, the same from guest to signed in
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

**Cart keyed by the Poppy Session, so a guest's cart follows the agent into the customer's account**

```ts
const poppy = await auth0.poppy.getContext();
const cartKey =
  poppy.kind === "agent"
    ? `${poppy.act.sub}|${poppy.act.poppy_sid}`
    : (await auth0.getSession())?.user.sub;
```

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
| Lifetime | Until the join's tokens expire (Auth0 caps them at 2 hours). Never renewed | The same. Rolling can't extend it past that |
| `onCallback`, `beforeSessionSaved` | **Not called**: both receive a user session, so a hook written for people could treat the guest as a customer | Called as usual |
| Agent state | Inside the guest cookie | In `session.internal.poppy`. `beforeSessionSaved` and `updateSession` can't remove it |

When the customer approves the agent and it joins again, the SDK replaces the guest with the customer's session and deletes the guest cookie, even if `clearAnonymousSessionOnLogin` is `false`.

**A guest and a session are never in the browser together.** A guest join ends any session the browser already has, a person's or a signed-in agent's, so the agent never acts with an account it wasn't approved for. The Poppy spec says a join SHOULD keep the browser's own login; the SDK ends it for that reason. The other way round, every login deletes the guest cookie: the usual redirect, a popup, a passkey and passwordless.

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
| Popup callback | `poppy_guest_not_supported` (`PoppyError`) | A guest login in a popup |
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

- **No refresh token.** Auth0 issues no refresh token for a join. For a signed-in agent, `getAccessToken()` can't refresh the token or get one for another audience, and the token lasts as long as the session, at most 2 hours. A login for an API the customer didn't approve for the agent fails with an authorization error.
- **Disconnecting.** Only revoking the agent's refresh token ends the browser's sign-in early. Removing a grant or blocking the user doesn't. Tokens from the join last at most 2 hours.
- **`protected_resources`.** Agents check that Auth0's metadata lists your domain there. Until Auth0 publishes it, agents may not trust your site.
- **Popups.** A signed-in agent that merges into an existing session in a popup doesn't get agent state.
- **Back-channel logout.** It doesn't reach guests, which live only in the browser's guest cookie.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `/.well-known/*` returns 404 | The `poppy` option isn't set, or the middleware matcher excludes `/.well-known/*` |
| A startup warning about `basePath`, or agents can't find the files | Agents fetch `/.well-known/*` at the host root, which an app with a `basePath` never receives. Serve the files at the root another way, such as a rewrite or a proxy |
| 500 at startup with `Invalid poppy.config: …` | The config is invalid. The message names the fix |
| Agents ignore the site | `issuer` doesn't match Auth0's character for character, or the site isn't on a public HTTPS host without a port |
| `/auth/login` fails with "An error occurred while trying to initiate the login request." | The server can't reach your tenant. Check the server log for the underlying error |
| The callback fails with `invalid_poppy_guest` | Read the server log, or `error.reason` in your `onCallback`. It names the failing check |
| The agent lands on your home page after a join, not the page it asked for | The join didn't send `iss`, or `iss` doesn't match your issuer, so `target_link_uri` was ignored. A mismatched `iss` logs a warning; a missing one doesn't |
| `poppy.getContext()` throws `poppy_not_enabled` | The `poppy` option isn't set, or `routes.poppyContext` is set to a path other than `NEXT_PUBLIC_POPPY_CONTEXT_ROUTE` |
| A signed-in agent's join fails at the callback | Auth0 needed to show a prompt, such as MFA, which an agent can't complete. Skip the prompt for these logins, for example in an Action |
| A guest isn't kept in the browser | The guest cookie is `Secure` by default, so serve the site over HTTPS |
