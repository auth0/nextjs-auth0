# with-mfa

A Next.js App Router example of MFA step-up with [`@auth0/nextjs-auth0`](https://github.com/auth0/nextjs-auth0). The user logs in without MFA. MFA is asked only when the app requests a token for a protected API.

## How it works

1. Login has no `audience`, so it needs no MFA.
2. `getAccessToken({ audience })` (from `@auth0/nextjs-auth0/client`) asks for a token for the protected API. Auth0 answers `mfa_required`, and the SDK throws an error that carries a sealed `mfa_token`.
3. `mfa.getAuthenticators({ mfaToken })` lists the user's authenticators.
4. `mfa.challenge({ mfaToken, challengeType, authenticatorId })` prepares the second factor.
5. `mfa.verify({ mfaToken, otp })` (or `oobCode` and `bindingCode`) checks the code. The token for the API is saved in the session.
6. Asking for the token again is served from the session, with no MFA.

`mfa.enroll()` adds an authenticator for a user who has none; it is not part of this example.

## Auth0 setup

1. A regular web application with the Authorization Code and Refresh Token grants, and the callback `http://localhost:3000/auth/callback` and logout URL `http://localhost:3000`.
2. An API with the identifier you put in `NEXT_PUBLIC_AUTH0_AUDIENCE`, and the application allowed to request it.
3. In the application's **Multi-Resource Refresh Token** settings, enable that API.
4. At least one MFA factor enabled (Security > Multi-factor Auth) and the user enrolled in it.
5. A post-login **Action** that asks for MFA on a refresh-token exchange, so that requesting the API's token answers `mfa_required`:

```js
exports.onExecutePostLogin = async (event, api) => {
  if (event.request?.body?.grant_type === "refresh_token") {
    if (event.user.enrolledFactors.length) {
      api.authentication.challengeWithAny([
        { type: "otp" }, { type: "phone" }, { type: "push-notification" },
        { type: "email" }, { type: "recovery-code" }
      ]);
    } else {
      api.authentication.enrollWithAny([
        { type: "otp" }, { type: "phone" }, { type: "push-notification" }
      ]);
    }
  }
};
```

The tenant's MFA policy must not be "Always": background token refreshes cannot answer an MFA challenge.

## Run it

```bash
cp .env.local.example .env.local   # fill in the values
pnpm install
pnpm dev
```

Open http://localhost:3000, log in, and click "Get a token for the API".
