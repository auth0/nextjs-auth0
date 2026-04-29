# Auth0 Next.js mTLS Example

This example demonstrates **Mutual TLS (mTLS) client authentication** with the Auth0 Next.js SDK using the App Router.

With mTLS, your application authenticates to Auth0 using a **TLS client certificate** instead of a client secret. Auth0 issues **certificate-bound access tokens** (RFC 8705) that include a `cnf.x5t#S256` claim, enabling strong proof-of-possession protection against token theft.

---

## Prerequisites

### 1. Auth0 Enterprise Plan with Custom Domain

mTLS requires:
- ✅ **Auth0 Enterprise plan**
- ✅ **Custom domain** (e.g., `auth.yourcompany.com`)
- ✅ **mTLS enabled** on your tenant

**Verify mTLS is enabled:**

```bash
curl -s https://auth.yourcompany.com/.well-known/openid-configuration | \
  python3 -c "import sys,json; print('mTLS enabled:', 'mtls_endpoint_aliases' in json.load(sys.stdin))"
```

**Must show:** `mTLS enabled: True`

### 2. Auth0 Application Configuration

1. **Create Application:**
   - Dashboard → Applications → Create Application
   - Choose **"Regular Web Application"**

2. **Configure Settings:**
   - **Allowed Callback URLs:** `http://localhost:3000/auth/callback`
   - **Allowed Logout URLs:** `http://localhost:3000`
   - **Advanced Settings → OAuth:**
     - Token Endpoint Authentication Method: **"Self-Signed TLS Client Authentication"**

3. **Upload Certificate:**
   - Dashboard → Applications → Your App → Credentials
   - Click **"Add Credential"**
   - Choose **"Self-Signed Certificate"**
   - Upload your `client.crt` file

---

## Quick Start

### 1. Generate Client Certificate

```bash
# Create certs directory
mkdir -p certs

# Generate private key
openssl genrsa -out certs/client.key 2048

# Generate self-signed certificate (valid 365 days)
openssl req -new -x509 -key certs/client.key \
  -out certs/client.crt -days 365 \
  -subj "/CN=nextjs-mtls-example"

# Get fingerprint (verify this matches what you uploaded to Auth0)
openssl x509 -in certs/client.crt -noout -fingerprint -sha256
```

### 2. Configure Environment

Edit `.env.local` and set your Auth0 values:

```bash
AUTH0_DOMAIN=auth.yourcompany.com  # Your custom domain with mTLS
AUTH0_CLIENT_ID=your-client-id
AUTH0_SECRET=$(openssl rand -hex 32)
```

### 3. Install Dependencies

```bash
pnpm install
```

### 4. Run the Application

```bash
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000), click **"Sign in"**, and authenticate.

---

## How It Works

### Code Implementation

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

// 2. Custom fetch using the TLS agent
function mtlsFetch(input: RequestInfo | URL, init?: RequestInit) {
  return undiciFetch(input, { ...init, dispatcher: tlsAgent });
}

// 3. Configure Auth0Client with mTLS
export const auth0 = new Auth0Client({
  useMtls: true,           // Use TlsClientAuth(), no client_secret
  customFetch: mtlsFetch,  // All requests use client certificate
});
```

### Authentication Flow

```
1. Browser → /authorize (regular HTTPS, NO certificate needed)
   User logs in via Auth0 Universal Login
   ↓
2. Auth0 redirects → /auth/callback?code=xyz
   ↓
3. Next.js Server → /oauth/token (WITH certificate via undici) ← mTLS HERE!
   Auth0 validates certificate fingerprint
   ↓
4. ✅ Certificate-bound tokens issued with cnf.x5t#S256 claim
```

**Key Point:** The browser **never** needs the certificate. Only the Next.js server uses mTLS during token exchange.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH0_DOMAIN` | ✅ | Custom domain with mTLS enabled |
| `AUTH0_CLIENT_ID` | ✅ | Application client ID |
| `AUTH0_SECRET` | ✅ | Session encryption secret |
| `APP_BASE_URL` | ✅ | Base URL (e.g., `http://localhost:3000`) |
| `MTLS_CLIENT_CERT_PATH` | ✅ | Path to client certificate PEM file |
| `MTLS_CLIENT_KEY_PATH` | ✅ | Path to private key PEM file |
| `MTLS_CA_CERT_PATH` | ○ | Optional: CA bundle for verification |
| `AUTH0_AUDIENCE` | ○ | Optional: API audience for resource server tokens |

---

## Troubleshooting

### "Invalid state data" Error

**Cause:** OAuth state parameter not found in cookies.

**Solution:**
- Clear browser cookies for localhost
- Ensure cookies are enabled
- For HTTP (localhost), set `AUTH0_COOKIE_SECURE=false` in `.env.local`

### "invalid_client" Error

**Possible causes:**

1. **Certificate not uploaded to Auth0**
   - Verify in Dashboard → Applications → Credentials

2. **Fingerprint mismatch**
   ```bash
   openssl x509 -in certs/client.crt -noout -fingerprint -sha256
   ```
   Must match fingerprint in Auth0 Dashboard

3. **Wrong authentication method**
   - Settings → Advanced → OAuth
   - Must be "Self-Signed TLS Client Authentication"

4. **No `mtls_endpoint_aliases`**
   - Verify custom domain has mTLS enabled
   - Contact Auth0 support if missing

### Browser Login Fails

**Check:**
1. ✅ Using custom domain (not `dev-xxx.auth0.com`)
2. ✅ `mtls_endpoint_aliases` in discovery document
3. ✅ Certificate uploaded to Auth0
4. ✅ Callback URL whitelisted

---

## Production Deployment

### Security Best Practices

1. **Store certificates securely:**
   - Use environment variables or secrets management
   - Never commit certificates to git

2. **Certificate rotation:**
   - Upload new certificate to Auth0 before expiration
   - Update environment variables
   - Restart application

3. **Verify configuration:**
   ```bash
   # Ensure custom domain
   echo $AUTH0_DOMAIN
   
   # Verify mTLS endpoints
   curl -s https://$AUTH0_DOMAIN/.well-known/openid-configuration | \
     grep mtls_endpoint_aliases
   ```

---

## Additional Resources

- [Auth0 mTLS Documentation](https://auth0.com/docs/get-started/applications/configure-mtls)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [undici Documentation](https://undici.nodejs.org/)

---

## Summary

✅ **Production-ready mTLS authentication**  
✅ **Certificate-bound access tokens** (RFC 8705)  
✅ **No client secrets** - certificate authenticates  
✅ **Enhanced security** - proof-of-possession protection

**For browser login to work, you MUST have:**

### 1. Custom Domain with mTLS Enabled

- ❌ **NOT** a default Auth0 domain (`dev-xxx.us.auth0.com`)
- ✅ **MUST BE** a custom domain (`auth.yourcompany.com`)
- Requires **Auth0 Enterprise plan**

### 2. Discovery Document with `mtls_endpoint_aliases`

Verify your custom domain has mTLS enabled:

```bash
curl -s https://auth.yourcompany.com/.well-known/openid-configuration | \
  python3 -c "import sys,json; print('mTLS enabled:', 'mtls_endpoint_aliases' in json.load(sys.stdin))"
```

**Must show:** `mTLS enabled: True`

### 3. How mTLS Works in Production

```
1. Browser → /authorize (regular HTTPS, NO certificate needed)
   User logs in via Auth0 Universal Login
   ↓
2. Auth0 redirects → /auth/callback?code=xyz (regular HTTP)
   ↓
3. Next.js Server → /oauth/token (WITH certificate via undici) ← mTLS HERE!
   Auth0 validates certificate fingerprint
   ↓
4. ✅ Certificate-bound tokens issued
```

**Key Point:** The browser **never** needs the certificate. Only the Next.js server uses mTLS during token exchange.

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

### Option 1: Full Browser Login (Requires Production Auth0 with mTLS)

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

### Option 2: Test Certificate Setup (No Full Auth0 Setup Needed)

If you don't have a custom domain with mTLS configured yet, you can still validate your certificate setup:

```bash
# 1. Install and generate certificate
pnpm install
mkdir -p certs
openssl genrsa -out certs/client.key 2048
openssl req -new -x509 -key certs/client.key -out certs/client.crt -days 365 -subj "/CN=test"

# 2. Configure minimal environment
cp .env.local.example .env.local
# Edit .env.local and set certificate paths:
#   MTLS_CLIENT_CERT_PATH=./certs/client.crt
#   MTLS_CLIENT_KEY_PATH=./certs/client.key

# 3. Start the app
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000) and click **"🔒 Test Certificate Setup"** button.

**What this validates:**
- ✅ Certificate attachment works (undici Agent)
- ✅ TLS handshake presents certificate correctly
- ✅ Server-side mTLS plumbing is functional
- ✅ Certificate fingerprint is displayed

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

## Testing

### 1. Test Certificate Setup (In-App)

The example includes an **interactive test button** to validate your certificate configuration:

1. Start the app: `pnpm run dev`
2. Open [http://localhost:3000](http://localhost:3000)
3. Click **"🔒 Test Certificate Setup"**

This creates a local HTTPS server that requests a client certificate, then verifies it's correctly attached via the undici Agent.

**Expected result:**
- ✅ Success message: "Certificate successfully attached and validated"
- ✅ Displays certificate fingerprint (SHA-256)
- ✅ Shows certificate subject (CN, O, etc.)

**What this validates:**
- Certificate files are readable and valid
- undici Agent correctly attaches certificate to TLS handshake
- Server-side mTLS plumbing works correctly
- Ready for Auth0 integration

### 2. Full Browser Login (With Auth0)

Once Auth0 is configured with mTLS:

1. Ensure custom domain with `mtls_endpoint_aliases` is set up
2. Upload certificate to Auth0 Dashboard
3. Start app: `pnpm run dev`
4. Open [http://localhost:3000](http://localhost:3000)
5. Click **"Sign in with Auth0"**

**Verify:**
- ✅ Login succeeds
- ✅ Profile is displayed
- ✅ Access token has `cnf.x5t#S256` claim (decode at [jwt.io](https://jwt.io))

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
- ✅ Server-to-server tests can still work
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

### Issue: Local tests pass but Auth0 login fails

**This means:**
- ✅ Your code is correct (certificate attachment works)
- ❌ Auth0 tenant not properly configured for mTLS

**Next steps:**
1. Verify `mtls_endpoint_aliases` in discovery document
2. Check certificate uploaded to Auth0
3. Verify Token Endpoint Authentication Method
4. Ensure custom domain is fully provisioned

---

## Current Limitations

### Without Production Auth0 mTLS:

- ❌ Browser login will fail
- ✅ In-app certificate test works ("Test Certificate Setup" button)
- ✅ Code implementation is complete and correct

### With Production Auth0 mTLS:

- ✅ Full browser login flow works
- ✅ Certificate-bound tokens issued
- ✅ No code changes needed (just update `AUTH0_DOMAIN`)

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

## Additional Resources

- [Auth0 mTLS Documentation](https://auth0.com/docs/get-started/applications/configure-mtls)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [undici Documentation](https://undici.nodejs.org/)

---

## Summary

This example demonstrates production-ready mTLS authentication with Auth0:

- ✅ **Code complete:** Uses undici to attach client certificates
- ✅ **Tested:** Local tests validate implementation
- ✅ **Production pattern:** Server-side mTLS, browser uses regular HTTPS
- ✅ **Certificate-bound tokens:** Enhanced security with proof-of-possession

**Requirements:**
- Custom domain with mTLS enabled in Auth0
- Auth0 Enterprise plan
- Client certificate generated and uploaded

**When properly configured, provides:**
- Strong client authentication without secrets
- Certificate-bound access tokens (RFC 8705)
- Protection against token theft and replay attacks
