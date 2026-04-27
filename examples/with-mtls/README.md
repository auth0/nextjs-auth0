# Auth0 Next.js mTLS Example

This example demonstrates **Mutual TLS (mTLS) client authentication** with the [Auth0 Next.js SDK](https://github.com/auth0/nextjs-auth0), using the App Router.

With mTLS enabled, the SDK authenticates to Auth0 using a **client TLS certificate** instead of a client secret. Auth0 issues **certificate-bound access tokens** (RFC 8705) carrying a `cnf.x5t#S256` claim — resource servers can validate that the presenter holds the matching private key, delivering strong proof-of-possession protection against token theft.

---

## What this example shows

- ✅ Configuring `useMtls: true` on `Auth0Client`
- ✅ Building an `undici` TLS agent that attaches the client certificate to every request
- ✅ Providing the agent as `customFetch` — no secret stored in environment variables
- ✅ Displaying the certificate-bound access token in the UI
- ✅ Standard login / logout flow via the SDK middleware

---

## Prerequisites

### 1. Auth0 tenant configuration

1. Go to **Dashboard → Settings → Advanced** and enable **mTLS**.
2. Open your application and set **Token Endpoint Auth Method** to **mTLS**.
3. Upload your client certificate (PEM) in **Credentials → Certificate**.

> **Note:** mTLS is available on Auth0 Enterprise plans. See  
> [Configure mTLS for Auth0](https://auth0.com/docs/get-started/applications/configure-mtls).

### 2. Generate a self-signed client certificate (for local testing)

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out certs/client.key 2048

# Self-signed certificate (valid 365 days)
openssl req -new -x509 -key certs/client.key \
  -out certs/client.crt -days 365 \
  -subj "/CN=nextjs-mtls-example"
```

> For production, use a certificate signed by a CA trusted by Auth0.

---

## Quick start

```bash
# 1. Install dependencies
npm install   # or pnpm install / yarn install

# 2. Configure environment variables
cp .env.local.example .env.local
# Edit .env.local — fill in AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_SECRET,
# APP_BASE_URL, MTLS_CLIENT_CERT_PATH, and MTLS_CLIENT_KEY_PATH.

# 3. Create the certs/ directory and generate a client certificate (see above)
mkdir -p certs

# 4. Start the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) and click **Sign in**.

After authentication you will see:

- Your Auth0 profile (from the ID token)
- The raw access token — decode it at [jwt.io](https://jwt.io) and inspect the `cnf.x5t#S256` claim confirming it is certificate-bound

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `AUTH0_DOMAIN` | ✅ | Your Auth0 tenant domain, e.g. `example.us.auth0.com` |
| `AUTH0_CLIENT_ID` | ✅ | Application client ID |
| `AUTH0_SECRET` | ✅ | 32-byte secret for session encryption (`openssl rand -hex 32`) |
| `APP_BASE_URL` | ✅ | Base URL of your app, e.g. `http://localhost:3000` |
| `MTLS_CLIENT_CERT_PATH` | ✅ | Absolute or relative path to the PEM client certificate |
| `MTLS_CLIENT_KEY_PATH` | ✅ | Absolute or relative path to the PEM private key |
| `MTLS_CA_CERT_PATH` | ○ | Path to a CA bundle for mutual verification (optional) |
| `AUTH0_AUDIENCE` | ○ | API audience — enables resource API tokens |

> **No `AUTH0_CLIENT_SECRET`** — with mTLS, the TLS certificate is the sole client credential.

---

## How it works

```
Browser ──login──▶ /auth/login ──▶ Auth0 /authorize
                                         │
                              Auth0 ◀──callback── /auth/callback
                                         │ (token request via mTLS)
                                         │ client cert ──▶ Auth0 validates
                                         │ Auth0 issues certificate-bound token
                              [session cookie] ◀── SDK writes session
```

The key pieces in [`lib/auth0.ts`](lib/auth0.ts):

1. **`undici` Agent** — wraps the client certificate so every TLS handshake presents it:
   ```ts
   const tlsAgent = new Agent({
     connect: { cert: readFileSync(certPath), key: readFileSync(keyPath) }
   });
   ```

2. **`customFetch`** — routes all SDK HTTP calls through the agent:
   ```ts
   function mtlsFetch(input, init) {
     return undiciFetch(input, { ...init, dispatcher: tlsAgent });
   }
   ```

3. **`Auth0Client` options**:
   ```ts
   export const auth0 = new Auth0Client({
     useMtls: true,       // use TlsClientAuth() + mTLS endpoint aliases
     customFetch: mtlsFetch,
   });
   ```

Inside the SDK, `useMtls: true`:
- Uses `oauth.TlsClientAuth()` — sends only `client_id` in the token request body (no secret)
- Sets `client.use_mtls_endpoint_aliases = true` — routes token requests to `mtls_endpoint_aliases.token_endpoint` from the Auth0 OIDC discovery document

---

## Testing the mTLS plumbing

Before testing against Auth0, verify that the `undici` agent + `customFetch` plumbing correctly attaches the client certificate:

```bash
node test-mtls.mjs
```

This script:
1. Spins up a local HTTPS server that **requests a client certificate** (mirrors an mTLS endpoint)
2. Uses the same `undici Agent` + `mtlsFetch` setup from [`lib/auth0.ts`](lib/auth0.ts)
3. Verifies the server receives the certificate and extracts its SHA-256 fingerprint

**Expected output:**
```
✅  Client cert was presented and accepted by the server.
    Fingerprint (SHA-256): 19:AB:D0:AC:...
```

If this passes, the SDK-side plumbing is correct. Any Auth0 login failures are due to:
- `mtls_endpoint_aliases` missing from Auth0's discovery document → tenant not fully provisioned for mTLS
- Certificate fingerprint mismatch → verify with `openssl x509 -in certs/client.crt -noout -fingerprint -sha256`
- Credential not uploaded or incorrect auth method in Auth0 Dashboard

### Debugging Auth0 mTLS

If the test script passes but Auth0 login fails:

1. **Check discovery document for mTLS endpoints:**
   ```bash
   curl -s https://<AUTH0_DOMAIN>/.well-known/openid-configuration | grep -i mtls
   ```
   
   You should see:
   ```json
   "mtls_endpoint_aliases": {
     "token_endpoint": "https://...",
     "userinfo_endpoint": "https://..."
   }
   ```
   
   If missing, mTLS is not fully provisioned on your tenant — contact Auth0 support or verify your plan includes mTLS.

2. **Verify certificate fingerprint matches:**
   ```bash
   openssl x509 -in certs/client.crt -noout -fingerprint -sha256 -subject
   ```
   
   Compare with what's shown in Auth0 Dashboard → Applications → Credentials.

3. **Test direct mTLS connection to Auth0:**
   ```bash
   curl -s --cert certs/client.crt --key certs/client.key \
     -X POST https://<AUTH0_DOMAIN>/oauth/token \
     -d "grant_type=client_credentials&client_id=<CLIENT_ID>"
   ```
   
   If this returns `{"error":"invalid_client"}` and the TLS handshake shows no `CertificateRequest` from the server, the tenant lacks dedicated mTLS infrastructure.

---

## Further reading

- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [Auth0 docs — Configure mTLS](https://auth0.com/docs/get-started/applications/configure-mtls)
- [nextjs-auth0 SDK — EXAMPLES.md](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#mtls)
- [undici documentation — Agent with TLS options](https://undici.nodejs.org/#/docs/api/Agent)
