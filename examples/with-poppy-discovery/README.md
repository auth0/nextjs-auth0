# with-poppy-discovery

Shows how to let personal AI agents shop on your Next.js site with the Poppy (Personal Agent Protocol) support in `@auth0/nextjs-auth0`. The SDK serves the discovery files agents read first, accepts an agent's browser login, and tells you whether a person or an agent is driving.

> **Beta.** Poppy support may change. See the [Poppy guide](../../guides/poppy.md) for the full picture.

## What's in here

| File | What it does |
| --- | --- |
| `poppy.json` | The Poppy discovery document, as `auth0 poppy config` writes it. The SDK serves it as is |
| `lib/auth0.ts` | Turns Poppy on with `new Auth0Client({ poppy: { config } })` |
| `proxy.ts` | Mounts the SDK. The default matcher lets `/.well-known/*` through |
| `app/page.tsx` | Calls `auth0.poppy.getContext()` to show who is driving, and offers Log in, or Log out for a person or an agent |
| `app/inspector.tsx`, `app/api/inspect/route.ts` | Buttons on the home page that call `auth0.poppy.getContext()`, `getSession()` and `getAnonymousSession()` on the server and show the result (tokens left out) |
| `app/browser-context.tsx` | A button that calls the client-side `poppy.getContext()`, which reads the SDK's `/auth/poppy-context` route |
| `app/cart/page.tsx` | Keys a cart by the Poppy session. For an agent guest it shows the cart manager below, and for anyone else a notice |
| `app/cart-manager.tsx` | The shop and cart UI: add items, change quantities, remove items, clear the cart |
| `lib/carts.ts`, `app/api/cart/**` | Server routes that call the carts API with the guest's access token. The browser never sees the token |

## Run it

1. Copy `.env.example` to `.env.local` and fill in your Auth0 application's values.
2. In your Auth0 application, add `http://localhost:3000/auth/callback` to the allowed callback URLs and `http://localhost:3000` to the allowed logout URLs.
3. In `poppy.json`, replace the placeholders with your values, or generate it with `auth0 poppy config` (see [The config file](#the-config-file)). For local testing set `organization.domain` to `localhost:3000`.
4. Install and start:

   ```bash
   pnpm install
   pnpm dev
   ```

Open [http://localhost:3000](http://localhost:3000). Log in and you're shown as a person. Click the buttons to see what each SDK method returns for your browser, and open `/.well-known/poppy.json` to see the discovery file.

While an agent guest is in the browser, **Log in** is refused with `poppy_sign_in_required`: only a signed-in agent join, or a new guest join, can replace the guest. The same applies to a protected page, which would otherwise loop. **Log out** ends the guest, through Auth0's `/v2/logout`.

## The config file

`poppy.json` is your Poppy discovery document, in the format `auth0 poppy config` writes. The one here is a sample: replace the placeholders with your values, or generate your own:

```bash
auth0 poppy config --company-domain <your-domain> --out ./poppy.json
auth0 poppy doctor <your-domain> --config ./poppy.json
```

It holds no secrets. The SDK serves it unchanged at `/.well-known/poppy.json`, and reads only two values from it:

| Field | What to put | Used for |
| --- | --- | --- |
| `organization.domain` | The host that serves your site: no scheme or path, and a port only when it isn't 443. For local testing only, `localhost:3000` | `resource` in `oauth-protected-resource` |
| `auth.issuer` | Your Auth0 issuer **exactly as Auth0 publishes it, including the trailing slash** | `authorization_servers`, and checking a join's `iss` |

The SDK checks these two at startup and throws `InvalidConfigurationError` with the fix. `auth0 poppy doctor` checks the rest. Set `web.unscoped` to `true`, as in the sample: this app gives a signed-in agent the account's full access.

## The cart (agent guests only)

> **The cart is stored in memory.** The app remembers which cart belongs to which Poppy session in a `Map` in the server process (`lib/carts.ts`). It is lost when the server restarts, and it is not shared between instances, so on a serverless host such as Vercel a cart can look empty on the next request. This is for the demo only: use your own storage (a database or Redis) in a real app.

The `/cart` page lets an agent guest manage a cart through a separate carts API, a small Express resource server that expects an Auth0 access token for its audience.

1. Start the carts API on `http://localhost:4000` (set `CARTS_API_URL` if it runs elsewhere).
2. Set `AUTH0_AUDIENCE` in `.env.local` to the carts API's identifier, so the access token an agent guest gets from the join is valid for it. Leave it unset if your tenant's default audience already is that API.
3. Make sure your tenant lets the web application get that API's token as an anonymous user.

The page calls `auth0.getAnonymousSession()` for the guest's access token and sends it as a Bearer token from the server. Anyone who isn't an agent guest gets a 403 from `/api/cart`, and the page shows a notice instead of the shop.

The carts API lists every cart to every caller, so the app never lists carts. It remembers which cart belongs to which Poppy session and only touches that one (see the note above about where that map lives).

## Try it with an agent

An agent only reaches your site over public HTTPS. To see an agent show up as **Agent · guest** and then **Agent · signed in**, you need:

- a tenant with Poppy enabled and an agent registered on it,
- this app on a public HTTPS host (a tunnel works),
- `organization.domain` in `poppy.json` set to that host.

The [Poppy guide](../../guides/poppy.md) covers each step, local testing and troubleshooting.
