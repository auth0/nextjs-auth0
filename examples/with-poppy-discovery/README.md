# with-poppy-discovery

Shows how to let personal AI agents shop on your Next.js site with the Poppy (Personal Agent Protocol) support in `@auth0/nextjs-auth0`. The SDK serves the discovery files agents read first, accepts an agent's browser login, and tells you whether a person or an agent is driving.

> **Experimental.** Poppy support is pinned to protocol version `0.3` and may change. See the [Poppy guide](../../guides/poppy.md) for the full picture.

## What's in here

| File | What it does |
| --- | --- |
| `auth0-poppy.json` | The Poppy configuration: your domain, Auth0 issuer, join endpoint and scopes |
| `lib/auth0.ts` | Turns Poppy on with `new Auth0Client({ poppy: { config } })` |
| `proxy.ts` | Mounts the SDK. The default matcher lets `/.well-known/*` through |
| `app/page.tsx` | Calls `auth0.getPoppyContext()` to show who is driving |
| `app/inspector.tsx`, `app/api/inspect/route.ts` | Buttons on the home page that call `getPoppyContext()`, `getSession()` and `getAnonymousSession()` and show the result (tokens left out) |
| `app/cart/page.tsx` | Keys a cart by the Poppy session, so a guest agent's cart follows it into the customer's account |

## Run it

1. Copy `.env.example` to `.env.local` and fill in your Auth0 application's values.
2. In your Auth0 application, add `http://localhost:3000/auth/callback` to the allowed callback URLs and `http://localhost:3000` to the allowed logout URLs.
3. In `auth0-poppy.json`, set `issuer` and `browserSessionEndpoint` to your tenant. The issuer must match Auth0's exactly, including the trailing slash.
4. Install and start:

   ```bash
   pnpm install
   pnpm dev
   ```

Open [http://localhost:3000](http://localhost:3000). Log in and you're shown as a person. Click the buttons to see what each SDK method returns for your browser, and open `/.well-known/poppy.json` to see the discovery file.

## Try it with an agent

An agent only reaches your site over public HTTPS. To see an agent show up as **Agent · guest** and then **Agent · signed in**, you need:

- a tenant with Poppy enabled and an agent registered on it,
- this app on a public HTTPS host (a tunnel works),
- `domain` in `auth0-poppy.json` set to that host, without a port.

The [Poppy guide](../../guides/poppy.md) covers each step, local testing and troubleshooting.
