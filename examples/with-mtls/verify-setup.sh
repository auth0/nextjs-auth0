#!/bin/bash
# mTLS Setup Verification Script
# Run this to check if your environment is ready for testing

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 Auth0 mTLS Setup Verification"
echo "================================"
echo ""

# Check if .env.local exists
if [ ! -f .env.local ]; then
  echo -e "${RED}❌ .env.local not found${NC}"
  echo "   Copy .env.local.example to .env.local and configure it"
  exit 1
fi

# Load environment variables
set -a
source .env.local
set +a

# 1. Check AUTH0_DOMAIN
echo "1️⃣  Checking AUTH0_DOMAIN..."
if [ -z "$AUTH0_DOMAIN" ]; then
  echo -e "${RED}   ❌ AUTH0_DOMAIN not set${NC}"
  exit 1
fi

echo "   Domain: $AUTH0_DOMAIN"

# 2. Test DNS resolution
echo ""
echo "2️⃣  Testing DNS resolution..."
if host "$AUTH0_DOMAIN" > /dev/null 2>&1; then
  echo -e "${GREEN}   ✅ Domain resolves${NC}"
  IP=$(host "$AUTH0_DOMAIN" | grep "has address" | head -1 | awk '{print $NF}')
  echo "   IP: $IP"
else
  echo -e "${RED}   ❌ Domain does not resolve${NC}"
  echo "   This must be a working custom domain in Auth0"
  exit 1
fi

# 3. Check HTTPS connectivity
echo ""
echo "3️⃣  Testing HTTPS connectivity..."
if curl -s --max-time 5 "https://$AUTH0_DOMAIN" > /dev/null 2>&1; then
  echo -e "${GREEN}   ✅ HTTPS accessible${NC}"
else
  echo -e "${RED}   ❌ Cannot connect to https://$AUTH0_DOMAIN${NC}"
  exit 1
fi

# 4. Check discovery document
echo ""
echo "4️⃣  Checking OpenID discovery document..."
DISCOVERY=$(curl -s "https://$AUTH0_DOMAIN/.well-known/openid-configuration")

if [ -z "$DISCOVERY" ]; then
  echo -e "${RED}   ❌ Cannot fetch discovery document${NC}"
  exit 1
fi

echo -e "${GREEN}   ✅ Discovery document accessible${NC}"

# 5. Check for mtls_endpoint_aliases
echo ""
echo "5️⃣  Checking mTLS endpoint aliases..."
MTLS_ENDPOINT=$(echo "$DISCOVERY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls_endpoint_aliases', {}).get('token_endpoint', ''))" 2>/dev/null || echo "")

if [ -z "$MTLS_ENDPOINT" ]; then
  echo -e "${RED}   ❌ No mtls_endpoint_aliases found${NC}"
  echo "   This means mTLS is NOT enabled on your custom domain"
  echo ""
  echo "   📋 Required steps:"
  echo "      1. Go to Auth0 Dashboard → Branding → Custom Domains"
  echo "      2. Verify your custom domain is 'Ready'"
  echo "      3. Enable mTLS (may require enterprise plan)"
  echo "      OR"
  echo "      1. Go to Settings → Advanced"
  echo "      2. Enable 'Require mTLS for token endpoint'"
  echo ""
  exit 1
else
  echo -e "${GREEN}   ✅ mTLS endpoints configured${NC}"
  echo "   Token endpoint: $MTLS_ENDPOINT"
fi

# 6. Check supported auth methods
echo ""
echo "6️⃣  Checking supported authentication methods..."
AUTH_METHODS=$(echo "$DISCOVERY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('token_endpoint_auth_methods_supported', [])))" 2>/dev/null || echo "")

if echo "$AUTH_METHODS" | grep -q "self_signed_tls_client_auth"; then
  echo -e "${GREEN}   ✅ self_signed_tls_client_auth supported${NC}"
else
  echo -e "${YELLOW}   ⚠️  self_signed_tls_client_auth NOT in supported methods${NC}"
fi

if echo "$AUTH_METHODS" | grep -q "tls_client_auth"; then
  echo -e "${GREEN}   ✅ tls_client_auth supported${NC}"
else
  echo -e "${YELLOW}   ⚠️  tls_client_auth NOT in supported methods${NC}"
fi

# 7. Check certificate files
echo ""
echo "7️⃣  Checking certificate files..."

if [ -z "$MTLS_CLIENT_CERT_PATH" ]; then
  echo -e "${RED}   ❌ MTLS_CLIENT_CERT_PATH not set${NC}"
  exit 1
fi

if [ -z "$MTLS_CLIENT_KEY_PATH" ]; then
  echo -e "${RED}   ❌ MTLS_CLIENT_KEY_PATH not set${NC}"
  exit 1
fi

if [ ! -f "$MTLS_CLIENT_CERT_PATH" ]; then
  echo -e "${RED}   ❌ Certificate not found: $MTLS_CLIENT_CERT_PATH${NC}"
  echo ""
  echo "   📋 Generate a self-signed certificate:"
  echo "      mkdir -p certs"
  echo "      openssl genrsa -out certs/client.key 2048"
  echo "      openssl req -new -x509 -key certs/client.key \\"
  echo "        -out certs/client.crt -days 365 \\"
  echo "        -subj \"/CN=nextjs-mtls-example\""
  exit 1
fi

if [ ! -f "$MTLS_CLIENT_KEY_PATH" ]; then
  echo -e "${RED}   ❌ Private key not found: $MTLS_CLIENT_KEY_PATH${NC}"
  exit 1
fi

echo -e "${GREEN}   ✅ Certificate found: $MTLS_CLIENT_CERT_PATH${NC}"
echo -e "${GREEN}   ✅ Private key found: $MTLS_CLIENT_KEY_PATH${NC}"

# 8. Verify certificate details
echo ""
echo "8️⃣  Certificate details..."

SUBJECT=$(openssl x509 -in "$MTLS_CLIENT_CERT_PATH" -noout -subject 2>/dev/null | sed 's/subject=//')
echo "   Subject: $SUBJECT"

ISSUER=$(openssl x509 -in "$MTLS_CLIENT_CERT_PATH" -noout -issuer 2>/dev/null | sed 's/issuer=//')
echo "   Issuer: $ISSUER"

NOT_AFTER=$(openssl x509 -in "$MTLS_CLIENT_CERT_PATH" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
echo "   Valid until: $NOT_AFTER"

FINGERPRINT=$(openssl x509 -in "$MTLS_CLIENT_CERT_PATH" -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
echo "   SHA-256 Fingerprint: $FINGERPRINT"

# Check if self-signed
if [ "$SUBJECT" = "$ISSUER" ]; then
  echo -e "${YELLOW}   ℹ️  Self-signed certificate${NC}"
  echo "   Application Token Endpoint Auth Method should be:"
  echo "   'Self-Signed TLS Client Authentication'"
else
  echo -e "${GREEN}   ✅ CA-issued certificate${NC}"
  echo "   Application Token Endpoint Auth Method should be:"
  echo "   'TLS Client Authentication'"
fi

# 9. Test certificate with Auth0
echo ""
echo "9️⃣  Testing mTLS connection to Auth0..."

if [ -z "$AUTH0_CLIENT_ID" ]; then
  echo -e "${YELLOW}   ⚠️  AUTH0_CLIENT_ID not set, skipping connection test${NC}"
else
  RESPONSE=$(curl -s -w "\n%{http_code}" \
    --cert "$MTLS_CLIENT_CERT_PATH" \
    --key "$MTLS_CLIENT_KEY_PATH" \
    -X POST "https://$AUTH0_DOMAIN/oauth/token" \
    -d "grant_type=client_credentials&client_id=$AUTH0_CLIENT_ID" 2>/dev/null)
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n-1)
  
  if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}   ✅ Auth0 accepted the certificate!${NC}"
    echo "   Response: Token received"
  elif [ "$HTTP_CODE" = "401" ]; then
    if echo "$BODY" | grep -q "invalid_client"; then
      echo -e "${RED}   ❌ Auth0 rejected the certificate (invalid_client)${NC}"
      echo ""
      echo "   📋 Possible issues:"
      echo "      1. Certificate not uploaded to Auth0 Dashboard → Applications → Credentials"
      echo "      2. Fingerprint mismatch (check Dashboard shows: $FINGERPRINT)"
      echo "      3. Wrong Token Endpoint Auth Method selected"
      echo "      4. Application not configured for mTLS"
    else
      echo -e "${YELLOW}   ⚠️  Authentication failed (401)${NC}"
      echo "   Response: $BODY"
    fi
  else
    echo -e "${YELLOW}   ⚠️  Unexpected response (HTTP $HTTP_CODE)${NC}"
    echo "   Response: $BODY"
  fi
fi

# Summary
echo ""
echo "================================"
echo "📊 Summary"
echo "================================"
echo ""

if [ -n "$MTLS_ENDPOINT" ]; then
  echo -e "${GREEN}✅ Custom domain configured with mTLS${NC}"
  echo -e "${GREEN}✅ Certificate files present${NC}"
  echo ""
  echo "🚀 Next steps:"
  echo "   1. Verify certificate is uploaded in Auth0 Dashboard:"
  echo "      Dashboard → Applications → Your App → Credentials"
  echo "      Fingerprint should match: $FINGERPRINT"
  echo ""
  echo "   2. Set Token Endpoint Authentication Method:"
  echo "      Settings → Advanced → OAuth"
  if [ "$SUBJECT" = "$ISSUER" ]; then
    echo "      Select: 'Self-Signed TLS Client Authentication'"
  else
    echo "      Select: 'TLS Client Authentication'"
  fi
  echo ""
  echo "   3. Run local plumbing test:"
  echo "      node test-mtls.mjs"
  echo ""
  echo "   4. Start the app:"
  echo "      pnpm run dev"
  echo ""
else
  echo -e "${RED}❌ mTLS not properly configured${NC}"
  echo ""
  echo "Please enable mTLS on your custom domain in Auth0 Dashboard"
fi
