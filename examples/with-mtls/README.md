# Auth0 Next.js mTLS Example

This example demonstrates **Mutual TLS (mTLS) client authentication** with the Auth0 Next.js SDK using the App Router.

With mTLS, your application authenticates to Auth0 using a **TLS client certificate** instead of a client secret. Auth0 issues **certificate-bound access tokens** (RFC 8705) that include a `cnf.x5t#S256` claim, enabling strong proof-of-possession protection against token theft.

---

## Prerequisites

### Auth0 Configuration

1. **Set up custom domain:**
   - Dashboard → Branding → Custom Domains
   - Add your domain (e.g., `auth.yourcompany.com`)
   - Configure DNS (CNAME to Auth0)
   - Wait for SSL provisioning

2. **Enable mTLS on custom domain:**
   - Dashboard → Custom Domains → Enable mTLS
   - OR Settings → Advanced → "Require mTLS for token endpoint"

3. **Configure application:**
   - Settings → Advanced → OAuth
   - Token Endpoint Authentication Method: **"Self-Signed TLS Client Authentication"**
   - Callbacks: `http://localhost:3000/auth/callback`

4. **Upload certificate:**
   - Dashboard → Applications → Credentials → Add Credential
   - Type: Self-Signed Certificate
   - Upload your `client.crt` file

### Generate Client Certificate

```bash
# Create directory
mkdir -p certs

# Generate private key
openssl genrsa -out certs/client.key 2048

# Generate self-signed certificate (valid 365 days)
openssl req -new -x509 -key certs/client.key \
  -out certs/client.crt -days 365 \
  -subj "/CN=nextjs-mtls-example"

# Get fingerprint (upload this to Auth0)
openssl x509 -in certs/client.crt -noout -fingerprint -sha256
```

---

## Quick Start

```bash
# 1. Install dependencies
pnpm install

# 2. Generate certificate (see above)
mkdir -p certs
# ... run openssl commands ...

# 3. Configure environment
cp .env.local.example .env.local
# Edit .env.local:
#   AUTH0_DOMAIN=auth.yourcompany.com  (your custom domain with mTLS)
#   AUTH0_CLIENT_ID=your-client-id
#   AUTH0_SECRET=$(openssl rand -hex 32)

# 4. Start the app
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000), click **Sign in**, and authenticate.

After login, you'll see:
- Your Auth0 profile
- Access token with `cnf.x5t#S256` claim (decode at [jwt.io](https://jwt.io))

---

## How It Works

### Code Implementation

The example uses **undici** to attach the client certificate to all HTTPS requests:

```typescript
// lib/auth0.ts
import { Agent, fetch as undiciFetch } from "undici";

// 1. Create TLS agent with client certificate
const tlsAgent = new Agent({
  connect: {
    cert: readFileSync(process.env.MTLS_CLIENT_CERT_PATH),
    key: readFileSync(process.env.MTLS_CLIENT_KEY_PATH)
  }
});

// 2. Custom fetch that uses the TLS agent
function mtlsFetch(input: RequestInfo | URL, init?: RequestInit) {
  return undiciFetch(input, { ...init, dispatcher: tlsAgent });
}

// 3. Configure Auth0Client with mTLS
export const auth0 = new Auth0Client({
  useMtls: true,           // Use TlsClientAuth(), no client_secret
  customFetch: mtlsFetch,  // All requests use client certificate
});
```

### What `useMtls: true` Does

1. **Uses `TlsClientAuth()`** from oauth4webapi:
   - Sends only `client_id` in token request
   - **Does NOT send** `client_secret`
   - Certificate in TLS handshake is the authentication credential

2. **Routes to mTLS endpoints:**
   - Reads `mtls_endpoint_aliases` from Auth0 discovery document
   - Routes token requests to mTLS-enabled endpoints
   - Browser requests still use regular endpoints

### Token Exchange Flow

```
Next.js Server receives callback with authorization code
  ↓
SDK calls: POST /oauth/token
  ├─ Via: customFetch (undici with TLS agent)
  ├─ TLS Handshake: Client certificate attached
  ├─ Body: { grant_type: "authorization_code", code: "...", client_id: "..." }
  └─ NO client_secret
  ↓
Auth0 validates:
  ├─ TLS certificate fingerprint matches stored certificate
  ├─ Authorization code is valid
  └─ Redirect URI matches
  ↓
Auth0 issues tokens:
  ├─ access_token with cnf.x5t#S256 claim (certificate-bound)
  ├─ id_token
  └─ refresh_token
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH0_DOMAIN` | ✅ | Custom domain with mTLS enabled (e.g., `auth.yourcompany.com`) |
| `AUTH0_CLIENT_ID` | ✅ | Application client ID |
| `AUTH0_SECRET` | ✅ | Session encryption secret (`openssl rand -hex 32`) |
| `APP_BASE_URL` | ✅ | Base URL (e.g., `http://localhost:3000`) |
| `MTLS_CLIENT_CERT_PATH` | ✅ | Path to client certificate PEM file (e.g., `./certs/client.crt`) |
| `MTLS_CLIENT_KEY_PATH` | ✅ | Path to private key PEM file (e.g., `./certs/client.key`) |
| `MTLS_CA_CERT_PATH` | ○ | Optional: CA bundle for certificate verification |
| `AUTH0_AUDIENCE` | ○ | Optional: API audience for resource server tokens |

**Important:** Do NOT set `AUTH0_CLIENT_SECRET` when using mTLS.

---

## Troubleshooting

### Issue: Browser login fails with certificate errors

**Symptoms:**
- `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED`
- "Your connection is not private"
- "Access denied"

**Cause:** Your Auth0 domain does NOT have `mtls_endpoint_aliases` configured.

**Check:**
```bash
curl -s https://YOUR-DOMAIN/.well-known/openid-configuration | grep mtls_endpoint_aliases
```

**If empty/missing:**
- ❌ Browser login will NOT work
- **Solution:** Set up a custom domain with mTLS enabled (see Prerequisites)

---

### Issue: `invalid_client` error during token exchange

**Possible causes:**

1. **Certificate not uploaded to Auth0:**
   - Go to Dashboard → Applications → Credentials
   - Verify certificate is present with correct fingerprint

2. **Fingerprint mismatch:**
   ```bash
   # Get your local certificate fingerprint
   openssl x509 -in certs/client.crt -noout -fingerprint -sha256
   # Must match fingerprint in Auth0 Dashboard
   ```

3. **Wrong authentication method:**
   - Dashboard → Applications → Settings → Advanced → OAuth
   - Token Endpoint Authentication Method must be:
     - "Self-Signed TLS Client Authentication" (for self-signed certs)
     - OR "TLS Client Authentication" (for CA-issued certs)

4. **No `mtls_endpoint_aliases`:**
   - Verify custom domain has mTLS enabled
   - Contact Auth0 support if missing

---

## Production Deployment

When deploying to production:

1. **Store certificates securely:**
   - Use environment variables or secrets management
   - Never commit certificate files to git

2. **Certificate rotation:**
   - Self-signed certs: Upload new cert to Auth0, update env vars
   - CA-issued certs: Renew before expiration, may auto-rotate if CA is trusted

3. **Environment variables:**
   ```bash
   AUTH0_DOMAIN=auth.yourcompany.com
   AUTH0_CLIENT_ID=production-client-id
   MTLS_CLIENT_CERT_PATH=/secure/path/to/cert.pem
   MTLS_CLIENT_KEY_PATH=/secure/path/to/key.pem
   ```

4. **Next.js configuration:**
   - Ensure `serverExternalPackages: ["undici"]` in `next.config.ts`
   - Ensure middleware uses `runtime = "nodejs"`

---

## Limitations

### Intended Use Cases

RFC 8705 mTLS was designed for **confidential server-side clients** — primarily:

| Flow | mTLS support |
|---|---|
| Authorization code exchange | ✅ Full — `cnf.x5t#S256` issued |
| Refresh token grant | ✅ Full — `cnf.x5t#S256` issued |
| Client credentials (M2M) | ✅ Full — `cnf.x5t#S256` issued |
| Token revocation on logout | ✅ Full — routes to mTLS alias |

### Supported Interactive Flows

Auth0 accepts mTLS client authentication on most interactive endpoints. The SDK routes all token exchanges through `mtls_endpoint_aliases.token_endpoint` automatically:

| Flow | mTLS support | Notes |
|---|---|---|
| MFA step-up (`mfaVerify`) | ✅ | `/mfa/challenge` accepts mTLS; token exchange via mTLS alias |
| Passkey login (`passkeyGetToken`) | ✅ | `/passkey/challenge` and `/passkey/register` accept mTLS |
| Custom token exchange | ✅ | Token exchange via mTLS alias |

### One Known Gap: Passwordless Start

`POST /passwordless/start` is the only endpoint that does **not** accept mTLS client authentication — Auth0's passport strategy list for that route omits both mTLS strategies (`oauth2-ca-signed-mtls`, `oauth2-self-signed-mtls`). An mTLS-only client (no `clientSecret`) will receive `invalid_client` when calling `passwordlessStart`. The subsequent verify step (`passwordlessVerify`) routes through the token endpoint and works fine — but it is unreachable without a successful start.

### `client_credentials` Gap

The SDK does not currently expose a `clientCredentials()` method. Auth0 does issue `cnf.x5t#S256` for client credentials grants — this is the primary M2M use case. Support can be added when needed.

---

## Additional Resources

- [Auth0 mTLS Documentation](https://auth0.com/docs/get-started/applications/configure-mtls)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [undici Documentation](https://undici.nodejs.org/)

---

## Summary

This example demonstrates production-ready mTLS authentication with Auth0:

- ✅ **No client secrets** — certificate authenticates the server
- ✅ **Certificate-bound tokens** — RFC 8705 proof-of-possession
- ✅ **Production pattern** — server-side mTLS, browser uses regular HTTPS

**Requirements:**
- Auth0 Enterprise plan
- Custom domain with mTLS enabled
- Client certificate generated and uploaded to Auth0
