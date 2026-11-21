# with-connected-accounts

A Next.js App Router example of connected accounts and Token Vault with [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0).

## What it shows

- **Connect an account**: the `/auth/connect` route (`enableConnectAccountEndpoint: true`). The `connectAccount()` method does the same from your own code.
- **List and disconnect accounts**: `auth0.getConnectedAccounts()` and `auth0.disconnectAccount({ connection })`, in route handlers.
- **Get a token for the provider**: `auth0.getAccessTokenForConnection({ connection, login_hint? })`.

## Auth0 setup

1. A first-party, confidential application with the Authorization Code, Refresh Token and Token Vault grant types.
2. Activate the **My Account API** (Applications > APIs) and give the application access with the scopes `create:me:connected_accounts`, `read:me:connected_accounts` and `delete:me:connected_accounts`.
3. In the application's **Multi-Resource Refresh Token** settings, enable the My Account API.
4. A social connection with **your own keys** (Auth0's developer keys are not accepted), with **Connected Accounts for Token Vault** turned on under Purpose and the application enabled on it. See [Connected Accounts for Token Vault](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault).
5. Callback and logout URLs: `http://localhost:3000/auth/callback` and `http://localhost:3000`.

## Run it

```bash
cp .env.local.example .env.local   # fill in the values
pnpm install
pnpm dev
```

Open http://localhost:3000, log in, then use the buttons on the dashboard.

## Notes

- Do not call `getConnectedAccounts()`, `disconnectAccount()` or `getAccessTokenForConnection()` from a Server Component: they can refresh and rewrite the session cookie, which Server Components cannot do. Use route handlers or server actions, as this example does.
- A connection token should stay on the server. The example returns only its length and lifetime.
