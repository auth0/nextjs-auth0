# mTLS Testing Guide

This guide walks through testing the mTLS example in both supported scenarios:

1. **Self-signed certificate** (`self_signed_tls_client_auth`)
2. **CA-issued certificate** (`tls_client_auth`)

---

## Prerequisites Checklist

### ✅ Auth0 Tenant Setup

- [ ] **Custom domain configured and verified**
  - Dashboard → Branding → Custom Domains
  - Domain must be DNS-accessible (e.g., `auth.yourcompany.com`)
  - SSL certificate provisioned and verified
  - Status shows "Ready"

- [ ] **mTLS enabled on the custom domain**
  - Check if there's an mTLS toggle in the custom domain settings
  - OR check Settings → Advanced → "Require mTLS for token endpoint"

- [ ] **Verify discovery document shows mTLS endpoints**
  ```bash
  curl -s https://YOUR-CUSTOM-DOMAIN/.well-known/openid-configuration | grep mtls_endpoint_aliases
  ```
  Should return:
  ```json
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://YOUR-CUSTOM-DOMAIN/oauth/token",
    ...
  }
  ```

### ✅ Application Setup

- [ ] **Create/configure application in Auth0 Dashboard**
  - Application Type: Regular Web Application
  - Allowed Callback URLs: `http://localhost:3000/auth/callback`
  - Allowed Logout URLs: `http://localhost:3000`

- [ ] **Set Token Endpoint Authentication Method**
  - Settings → Advanced Settings → OAuth
  - For self-signed: Choose **"Self-Signed TLS Client Authentication"**
  - For CA-issued: Choose **"TLS Client Authentication"**

---

## Scenario 1: Self-Signed Certificate

### Step 1: Generate Self-Signed Certificate

```bash
cd examples/with-mtls

# Create certs directory
mkdir -p certs

# Generate private key (2048-bit RSA)
openssl genrsa -out certs/client.key 2048

# Generate self-signed certificate (valid 365 days)
openssl req -new -x509 -key certs/client.key \
  -out certs/client.crt -days 365 \
  -subj "/CN=nextjs-mtls-example/O=YourOrg/C=US"

# Verify the certificate
openssl x509 -in certs/client.crt -text -noout
```

### Step 2: Get Certificate Fingerprint

```bash
# SHA-256 fingerprint (Auth0 uses this)
openssl x509 -in certs/client.crt -noout -fingerprint -sha256

# Also get the subject
openssl x509 -in certs/client.crt -noout -subject
```

**Copy the fingerprint** — you'll need it for verification.

### Step 3: Upload Certificate to Auth0

1. **Dashboard → Applications → Your App → Credentials**
2. Click **"Add Credential"** or **"Upload Certificate"**
3. **Credential Type**: Self-Signed Certificate
4. **Upload**: Paste the contents of `certs/client.crt` OR upload the file
5. **Save**

**Verify the fingerprint matches** what you got from the `openssl` command.

### Step 4: Configure Environment

Edit `examples/with-mtls/.env.local`:

```bash
AUTH0_DOMAIN=your-custom-domain.com  # NOT the default dev-xxx.us.auth0.com
AUTH0_CLIENT_ID=<your-client-id>
AUTH0_SECRET=$(openssl rand -hex 32)
APP_BASE_URL=http://localhost:3000

MTLS_CLIENT_CERT_PATH=./certs/client.crt
MTLS_CLIENT_KEY_PATH=./certs/client.key
```

### Step 5: Test Locally

**A. Test SDK plumbing (local HTTPS server):**

```bash
cd examples/with-mtls
node test-mtls.mjs
```

Expected output:
```
✅  Client cert was presented and accepted by the server.
    Fingerprint (SHA-256): XX:XX:XX:...
```

**B. Test direct connection to Auth0:**

```bash
curl -v --cert certs/client.crt --key certs/client.key \
  -X POST https://YOUR-CUSTOM-DOMAIN/oauth/token \
  -d "grant_type=client_credentials&client_id=YOUR-CLIENT-ID" 2>&1 | grep -E "TLS|Certificate|< HTTP"
```

**What to look for:**
- `* TLSv1.3 (OUT), TLS handshake, Client certificate (11):` — cert is being sent
- `< HTTP/2 200` — success (returns tokens)
- **NOT** `< HTTP/2 401` with `invalid_client`

**C. Test the Next.js app:**

```bash
pnpm run dev
# Open http://localhost:3000
# Click "Sign in"
```

Expected flow:
1. Redirects to Auth0 login
2. Enter credentials
3. Callback succeeds (code exchange uses mTLS)
4. Shows profile + access token with `cnf.x5t#S256` claim

**D. Verify certificate binding:**

After logging in, copy the access token from the UI and decode at [jwt.io](https://jwt.io).

Look for the `cnf` claim:
```json
{
  "cnf": {
    "x5t#S256": "XX_XX_XX_..."
  }
}
```

The `x5t#S256` value should match your certificate fingerprint (base64url-encoded).

---

## Scenario 2: CA-Issued Certificate

### Step 1: Generate CSR and Get Certificate from CA

```bash
cd examples/with-mtls/certs

# Generate private key
openssl genrsa -out client-ca.key 2048

# Generate Certificate Signing Request (CSR)
openssl req -new -key client-ca.key -out client-ca.csr \
  -subj "/CN=nextjs-mtls-ca-example/O=YourOrg/C=US"

# Submit CSR to your Certificate Authority (CA)
# - For testing: Use Let's Encrypt, DigiCert, or your internal CA
# - CA will return: client-ca.crt (signed certificate)
#                   ca-bundle.crt (CA certificate chain)
```

**Save the CA-issued certificate and chain:**
- `client-ca.crt` — your client certificate
- `ca-bundle.crt` — CA's certificate chain (optional, for verification)

### Step 2: Configure Auth0 for CA-Issued Certificate

**Option A: Upload certificate (if Auth0 supports this for `tls_client_auth`):**

1. Dashboard → Applications → Your App → Credentials
2. Upload `client-ca.crt`
3. Token Endpoint Auth Method: **"TLS Client Authentication"** (not "Self-Signed")

**Option B: Configure trusted CA (tenant-level):**

Some Auth0 configurations require uploading the **CA's root certificate** to the tenant, and then Auth0 validates any client cert signed by that CA:

1. Dashboard → Settings → Advanced → Certificates
2. Upload the CA's root/intermediate certificate
3. Application Token Endpoint Auth Method: **"TLS Client Authentication"**

### Step 3: Update Environment Variables

Edit `.env.local`:

```bash
# Use CA-issued certificate paths
MTLS_CLIENT_CERT_PATH=./certs/client-ca.crt
MTLS_CLIENT_KEY_PATH=./certs/client-ca.key

# Optional: CA bundle for verification
MTLS_CA_CERT_PATH=./certs/ca-bundle.crt
```

### Step 4: Test CA-Issued Certificate

**A. Verify certificate chain:**

```bash
# Check the certificate was signed by the CA
openssl verify -CAfile certs/ca-bundle.crt certs/client-ca.crt
```

Should output: `certs/client-ca.crt: OK`

**B. Test against Auth0:**

```bash
curl -v --cert certs/client-ca.crt --key certs/client-ca.key \
  --cacert certs/ca-bundle.crt \
  -X POST https://YOUR-CUSTOM-DOMAIN/oauth/token \
  -d "grant_type=client_credentials&client_id=YOUR-CLIENT-ID" 2>&1 | grep -E "Certificate|< HTTP"
```

**C. Run the Next.js app:**

```bash
pnpm run dev
# Test login flow
```

---

## Comparison: Self-Signed vs CA-Issued

| Aspect | Self-Signed | CA-Issued |
|--------|-------------|-----------|
| **Auth Method** | `self_signed_tls_client_auth` | `tls_client_auth` |
| **Certificate Upload** | Must upload to Auth0 app credentials | May need CA root cert in tenant |
| **Verification** | Auth0 checks exact fingerprint match | Auth0 validates cert chain against trusted CA |
| **Production Use** | ❌ Not recommended | ✅ Recommended |
| **Setup Complexity** | Low (quick local testing) | Medium (need CA, cert chain) |
| **Certificate Rotation** | Manual (upload new cert to Auth0) | Automatic (if CA is trusted, just rotate locally) |

---

## Debugging Checklist

If login fails with `invalid_client` or `An error occurred while trying to exchange the authorization code`:

### 1. Verify Custom Domain Discovery

```bash
curl -s https://YOUR-CUSTOM-DOMAIN/.well-known/openid-configuration | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('mtls_endpoint_aliases:', d.get('mtls_endpoint_aliases', 'MISSING'))"
```

❌ If `MISSING`: mTLS not enabled on custom domain → check Auth0 Dashboard settings

### 2. Verify Certificate Fingerprint Matches

```bash
# Your local cert fingerprint
openssl x509 -in certs/client.crt -noout -fingerprint -sha256

# Compare with Auth0 Dashboard → Apps → Credentials
```

❌ If different: Re-upload the correct certificate

### 3. Verify Token Endpoint Auth Method

Dashboard → Applications → Your App → Settings → Advanced → OAuth

Should be:
- **Self-Signed TLS Client Authentication**, OR
- **TLS Client Authentication**

❌ If "Client Secret Post": Change to mTLS method

### 4. Test TLS Handshake Directly

```bash
openssl s_client -connect YOUR-CUSTOM-DOMAIN:443 \
  -cert certs/client.crt -key certs/client.key \
  -showcerts 2>&1 | grep -E "Verify return code|Server certificate"
```

Should show: `Verify return code: 0 (ok)`

### 5. Check SDK Logs

The example doesn't have debug logs enabled by default. To add temporary logging:

Edit `lib/auth0.ts` and wrap `mtlsFetch`:

```ts
function mtlsFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
  console.log('[mTLS] Fetching:', url);
  
  return undiciFetch(input as Parameters<typeof undiciFetch>[0], {
    ...(init as Parameters<typeof undiciFetch>[1]),
    dispatcher: tlsAgent
  }) as Promise<Response>;
}
```

Restart the dev server and check terminal output during login.

---

## Clean Testing Process

Before each test run:

```bash
# 1. Clear Next.js cache
rm -rf .next

# 2. Clear browser cookies/session for localhost:3000

# 3. Restart dev server
pnpm run dev

# 4. Test in incognito/private window
```

---

## Success Criteria

### ✅ Self-Signed Certificate Test Passes When:

1. Local test: `node test-mtls.mjs` → ✅ cert presented
2. Direct curl: Returns `200` with access token (not `401 invalid_client`)
3. Next.js login: Completes without errors
4. Access token has `cnf.x5t#S256` claim
5. Fingerprint in `cnf` matches your certificate

### ✅ CA-Issued Certificate Test Passes When:

1. Certificate chain validates: `openssl verify` → OK
2. Auth0 accepts cert during token exchange
3. Login flow completes
4. Access token has `cnf.x5t#S256` claim
5. Certificate can be rotated without re-uploading to Auth0 (if CA is trusted at tenant level)

---

## Next Steps After Testing

Once both scenarios pass:

1. Document any Auth0 tenant-specific configuration in a note
2. Add screenshots to the README (optional)
3. Commit the example to PR 5
4. Move to PR 6 (EXAMPLES.md + CHANGELOG.md updates)

---

## Known Issues / Limitations

- **Default Auth0 domains** (`dev-xxx.us.auth0.com`) don't support mTLS — custom domain required
- **Edge Runtime** doesn't support `fs.readFileSync` or undici — middleware must use Node.js runtime
- **Token rotation**: Self-signed certs require manual re-upload to Auth0 when rotated
- **Browser testing**: Client certs in browsers require different setup (this example is server-side only)
