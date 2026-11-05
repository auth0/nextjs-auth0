# Poppy (Personal Agents)

Examples for letting personal AI agents, such as Meta Muse, shop and manage accounts on your Next.js site through the Auth0 Next.js SDK, using the Poppy (Personal Agent Protocol).

> **Experimental.** Poppy support is pinned to protocol version `0.3` and may change without a major release. Poppy is in beta on Auth0, so your tenant needs it enabled.

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [How it works](#how-it-works)
- [Setup](#setup)
  - [1. Configure Auth0](#1-configure-auth0)
  - [2. Add `auth0-poppy.json`](#2-add-auth0-poppyjson)
  - [3. Turn it on](#3-turn-it-on)
- [The discovery files](#the-discovery-files)
- [Knowing who is driving](#knowing-who-is-driving)
- [Guests and signed-in agents](#guests-and-signed-in-agents)
- [Error handling](#error-handling)
- [Testing locally](#testing-locally)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## How it works

An agent reaches your site in two ways. It can call your APIs with a signed `Poppy-Session` header, which `@auth0/auth0-api-js` handles. Or it can drive a browser on your website, which is what the SDK handles and this guide covers.

1. The agent reads `/.well-known/poppy.json` and `/.well-known/oauth-protected-resource` on your domain. **The SDK serves both.**
2. The agent's browser opens an Auth0-hosted *join* page, and the agent's backend proves who it is to Auth0. **Auth0 verifies the agent. The SDK never sees that proof.**
3. Auth0 sends the browser to your `/auth/login`, then back to `/auth/callback`, and the SDK exchanges the code as for any login. **The SDK reads the agent from the ID token Auth0 signed.**
4. Your code asks `auth0.getPoppyContext()` who is driving.

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
  "protocolVersion": "0.3",
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
| `protocolVersion` | Only `"0.3"` is supported |
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

Your middleware matcher has to let `/.well-known/*` through to the SDK:

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
  "protocol_version": "0.3",
  "organization": { "name": "Fernway", "domain": "fernway.com" },
  "auth": { "issuer": "https://auth.fernway.com/", "scopes": { "orders:write": "Place orders" } },
  "web": { "browser_session_endpoint": "https://auth.fernway.com/poppy/<web-app-client-id>/browser-session" }
}

// GET /.well-known/oauth-protected-resource
{ "resource": "https://fernway.com", "authorization_servers": ["https://auth.fernway.com/"] }
```

Agents compare these with Auth0's own metadata character for character, and skip your site without saying why if anything differs.

## Knowing who is driving

`auth0.getPoppyContext()` mirrors `getSession()`: no argument in the App Router, and `req` in middleware and the Pages Router.

```ts
type PoppyContext =
  | { kind: "human" }
  | {
      kind: "agent";
      state: "guest" | "signed_in";
      agent: { clientId: string };   // the agent's client metadata URL
      poppy_sid: string;             // Poppy Session ID, the same from guest to signed in
      poppy_user_id: string;         // the agent's pairwise ID for this person
      poppy_agent_id?: string;       // which of the agent's agents, when it sent one
      scopes: string[];              // the website token's scopes; [] for a guest
    };
```

The Poppy IDs keep the names of the token claims they come from. `poppy_user_id` is not the customer's Auth0 user ID: that is `session.user.sub`.

**Server Component: show a banner to agents**

```tsx
const poppy = await auth0.getPoppyContext();
if (poppy.kind === "agent") {
  return <Banner>Browsing via {poppy.agent.clientId} ({poppy.state})</Banner>;
}
```

**Cart keyed by the Poppy Session, so a guest's cart follows the agent into the customer's account**

```ts
const poppy = await auth0.getPoppyContext();
const cartKey =
  poppy.kind === "agent"
    ? `${poppy.agent.clientId}|${poppy.poppy_sid}`
    : (await auth0.getSession())?.user.sub;
```

**Server Action: set your own rules for agents**

```ts
"use server";
export async function placeOrder(cart: Cart) {
  const poppy = await auth0.getPoppyContext();
  if (poppy.kind === "agent") {
    if (poppy.state === "guest") throw new Error("Sign in through your agent to order");
    await saveOrder(cart, { placedVia: poppy.agent.clientId });
    return;
  }
  await saveOrder(cart);
}
```

**Middleware and the Pages Router**

```ts
const poppy = await auth0.getPoppyContext(req);
```

`getPoppyContext()` always returns `{ kind: "human" }` when the `poppy` option isn't set. A signed-in session takes precedence over a guest cookie, so a person's own login is never reported as an agent.

The SDK keeps no storage of its own for Poppy Sessions. Where you keep carts and how you link a guest to a customer is up to your app, and `poppy_sid` is the key to use.

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

## Error handling

A login that looks like a guest (an `anon_poppy@` subject or Auth0's anonymous `sub_profile`) but isn't a valid Poppy guest is refused, and nothing is stored. The error is a `PoppyError`, so check `error.code`. Its message ends with `Reason: …`, which names the failing check. It lists claim names but never their values.

```ts
import { NextResponse } from "next/server";
import { PoppyErrorCode } from "@auth0/nextjs-auth0/errors";

export const auth0 = new Auth0Client({
  poppy: { config: poppyConfig },
  onCallback: async (error, context) => {
    if (error?.code === PoppyErrorCode.INVALID_GUEST) {
      console.error("Poppy login refused:", error.message);
      return new NextResponse(error.message, { status: 500 });
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

- **Agent scopes.** `getPoppyContext().scopes` are the scopes of the website's own token. At the time of writing they may not be what the customer approved for the agent, so don't use them to decide what an agent may do.
- **Disconnecting.** Only revoking the agent's refresh token ends the browser's sign-in early. Removing a grant or blocking the user doesn't. Tokens from the join last at most 2 hours.
- **`protected_resources`.** Agents check that Auth0's metadata lists your domain there. Until Auth0 publishes it, agents may not trust your site.
- **Popups.** A signed-in agent that merges into an existing session in a popup doesn't get agent state.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `/.well-known/*` returns 404 | The `poppy` option isn't set, or the middleware matcher excludes `/.well-known/*` |
| 500 at startup with `Invalid poppy.config: …` | The config is invalid. The message names the fix |
| Agents ignore the site | `issuer` doesn't match Auth0's character for character, or the site isn't on a public HTTPS host without a port |
| `/auth/login` fails with "An error occurred while trying to initiate the login request." | The server can't reach your tenant. Check the server log for the underlying error |
| The callback fails with `invalid_poppy_guest` | Read the `Reason:` at the end of the error message |
| A guest isn't kept in the browser | The guest cookie is `Secure` by default, so serve the site over HTTPS |
