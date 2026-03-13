# MFA Contract Parity: BREAKING CHANGES

**Status:** BREAKING CHANGE - No Backward Compatibility

**Date:** 2026-03-12

This document describes the breaking wire format changes to nextjs-auth0's MFA route handlers to align with Auth0's HTTP API contract.

## Overview

The nextjs-auth0 MFA SDK has been restructured to implement a **transparent proxy pattern** — enabling higher-level consumers to make Auth0-shaped HTTP requests to nextjs-auth0 route handlers and receive Auth0-shaped HTTP responses.

### What Changed

This is a **wire format only** change. The TypeScript SDK types (camelCase) remain unchanged. However:

1. **Request Format (BREAKING)**: MFA route handlers now accept ONLY snake_case request bodies and Authorization headers
2. **Response Format (BREAKING)**: MFA route handlers now return ONLY snake_case responses (matching Auth0 API format)
3. **Token Transport (BREAKING)**: MFA tokens MUST be passed via Authorization header, NOT query params or body
4. **New Capability**: Added `DELETE /auth/mfa/authenticators/{id}` endpoint for removing enrolled factors

### Architecture Pattern

```
┌─ SDK Consumer (camelCase types) ────────────────────────────┐
│                                                              │
│  Client SDK         ┌─ Transform to snake_case              │
│  (camelCase)        │                                        │
│                     ▼                                        │
│              Route Handler                                  │
│          (snake_case wire format)                           │
│                     │                                        │
│                     ├─ Validate snake_case only             │
│                     ├─ Extract Authorization header         │
│                     ├─ Call Auth0 API (raw mfa_token)       │
│                     │                                        │
│                     ▼                                        │
│              Response (snake_case)                          │
│                     │                                        │
│  Transparent        │  (Direct HTTP callers receive         │
│  Proxy Pattern      │   Auth0-format responses)             │
│                     ▼                                        │
│          Client SDK Transforms to camelCase                 │
│          (SDK users never see breaking changes)             │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

## Breaking Changes Summary

### 1. Query Parameter Fallback Removed

**Old:** MFA token accepted in:
- `?mfa_token=...` (query string)
- Body: `{ "mfaToken": "..." }` (camelCase)
- Authorization header (Bearer token)

**New:** MFA token ONLY accepted via:
- `Authorization: Bearer <mfa_token>` (REQUIRED)

**Error Response:** `401 Unauthorized`
```json
{
  "error": "invalid_request",
  "error_description": "Missing or invalid Authorization header"
}
```

### 2. Request Body Field Names (Snake_case Only)

**Breaking:** camelCase field names are NO LONGER accepted in request bodies.

| Endpoint | Old (camelCase) | New (snake_case) |
|----------|-----------------|------------------|
| Challenge | `mfaToken`, `challengeType`, `authenticatorId` | `mfa_token`, `challenge_type`, `authenticator_id` |
| Enroll | `authenticatorTypes`, `oobChannels`, `phoneNumber` | `authenticator_types`, `oob_channels`, `phone_number` |
| Verify | `oobCode`, `bindingCode`, `recoveryCode` | `oob_code`, `binding_code`, `recovery_code` |

### 3. Response Format (Snake_case Only)

**All MFA route handler responses now return snake_case fields.** This matches Auth0's HTTP API contract.

Example: `/auth/mfa/authenticators` response
```json
[
  {
    "id": "dev_abc123",
    "authenticator_type": "otp",
    "type": "otp",
    "active": true,
    "created_at": "2026-03-12T10:00:00Z",
    "last_auth": "2026-03-12T11:30:00Z"
  }
]
```

### 4. Token Type: mfa_token in Body (Challenge Endpoint Only)

**Challenge endpoint:** The MFA token must be passed in the request body as `mfa_token` (in addition to the Authorization header) to maintain Auth0 API compatibility.

```json
{
  "mfa_token": "<encrypted-token>",
  "challenge_type": "oob",
  "authenticator_id": "sms|dev_abc123"
}
```

## Wire Format Reference

### 1. GET /auth/mfa/authenticators

**Lists enrolled MFA authenticators.**

#### Request

```http
GET /auth/mfa/authenticators HTTP/1.1
Authorization: Bearer <mfa_token>
```

#### Response (200 OK)

```json
[
  {
    "id": "dev_abc123",
    "authenticator_type": "otp",
    "type": "otp",
    "active": true,
    "name": "Authenticator App",
    "created_at": "2026-03-12T10:00:00Z",
    "last_auth": "2026-03-12T11:30:00Z"
  },
  {
    "id": "sms|dev_xyz789",
    "authenticator_type": "oob",
    "type": "sms",
    "active": true,
    "oob_channel": "sms",
    "phone_number": "+1***1234",
    "created_at": "2026-03-11T09:15:00Z",
    "last_auth": "2026-03-12T14:22:00Z"
  }
]
```

#### Errors

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Missing Authorization header |
| 401 | `mfa_token_invalid` | Token cannot be decrypted |
| 401 | `mfa_token_expired` | Token TTL exceeded (>5 min) |
| 400 | `mfa_no_available_factors` | No challenge types in mfa_requirements |

---

### 2. POST /auth/mfa/challenge

**Initiates an MFA challenge (sends code via SMS, email, or push notification).**

#### Request

```http
POST /auth/mfa/challenge HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "mfa_token": "<mfa_token>",
  "challenge_type": "oob",
  "authenticator_id": "sms|dev_abc123"
}
```

#### Response (200 OK)

```json
{
  "challenge_type": "oob",
  "oob_code": "Fe26...Ha",
  "binding_method": "prompt"
}
```

#### Errors

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Missing required field (mfa_token, challenge_type) |
| 401 | `mfa_token_invalid` | Token cannot be decrypted |
| 401 | `mfa_token_expired` | Token TTL exceeded |
| 400 | `mfa_no_available_factors` | Challenge type not in mfa_requirements |
| 400 | `invalid_challenge_type` | Unsupported challenge type |

---

### 3. POST /auth/mfa/verify

**Verifies MFA code and returns authentication tokens.**

#### Request (OTP)

```http
POST /auth/mfa/verify HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "otp": "123456"
}
```

#### Request (OOB - SMS/Push/Email)

```http
POST /auth/mfa/verify HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "oob_code": "Fe26...Ha",
  "binding_code": "654321"
}
```

#### Request (Recovery Code)

```http
POST /auth/mfa/verify HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "recovery_code": "ABCD-EFGH-IJKL-MNOP"
}
```

#### Response (200 OK)

```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "openid profile email"
}
```

**With Session:** Session cookie also set via `Set-Cookie` header.

#### Errors

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Missing or invalid credential field |
| 401 | `mfa_token_invalid` | Token cannot be decrypted |
| 401 | `mfa_token_expired` | Token TTL exceeded |
| 403 | `invalid_grant` | Wrong MFA code |
| 403 | `mfa_required` | Additional factor required (chained MFA) |
| 429 | `too_many_requests` | Rate limit exceeded |

---

### 4. POST /auth/mfa/associate

**Associates a new MFA authenticator during initial MFA setup (Auth0-compliant naming).**

#### Request (OTP)

```http
POST /auth/mfa/associate HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "authenticator_types": ["otp"]
}
```

#### Request (OOB - SMS)

```http
POST /auth/mfa/associate HTTP/1.1
Content-Type: application/json
Authorization: Bearer <mfa_token>

{
  "authenticator_types": ["oob"],
  "oob_channels": ["sms"],
  "phone_number": "+15551234567"
}
```

#### Response: OTP Enrollment (200 OK)

```json
{
  "authenticator_type": "otp",
  "id": "dev_abc123",
  "secret": "JBSWY3DPEBLW64TMMQ======",
  "barcode_uri": "otpauth://totp/example%40example.com?secret=JBSWY3DPEBLW64TMMQ%3D%3D%3D%3D&issuer=Example",
  "recovery_codes": [
    "ABCD-EFGH-IJKL-MNOP",
    "PQRS-TUVW-XYZA-BCDE"
  ]
}
```

#### Response: OOB Enrollment (200 OK)

```json
{
  "authenticator_type": "oob",
  "id": "sms|dev_abc123",
  "oob_channel": "sms",
  "name": "SMS",
  "oob_code": "Fe26...Ha",
  "binding_method": "prompt",
  "recovery_codes": [
    "ABCD-EFGH-IJKL-MNOP",
    "PQRS-TUVW-XYZA-BCDE"
  ]
}
```

#### Errors

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Missing authenticator_types or invalid oob_channels |
| 401 | `mfa_token_invalid` | Token cannot be decrypted |
| 401 | `mfa_token_expired` | Token TTL exceeded |
| 400 | `invalid_phone` | Invalid phone number format |
| 400 | `unsupported_channel` | Unsupported OOB channel |

---

### 5. DELETE /auth/mfa/authenticators/{authenticatorId}

**Deletes an enrolled MFA authenticator. NEW endpoint.**

#### Request

```http
DELETE /auth/mfa/authenticators/sms|dev_abc123 HTTP/1.1
Authorization: Bearer <mfa_token>
```

#### Response (204 No Content)

```
(empty body)
```

#### Errors

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Missing Authorization header |
| 401 | `mfa_token_invalid` | Token cannot be decrypted |
| 401 | `mfa_token_expired` | Token TTL exceeded |
| 404 | `authenticator_not_found` | Authenticator doesn't exist |
| 400 | `cannot_delete_last_factor` | Cannot delete only enrolled factor |

---

## Migration Guide

### For SDK Users (Using Client SDK)

**No changes needed.** The client SDK automatically handles the transformation between camelCase and snake_case.

```typescript
// This code works exactly the same as before
import { mfa } from '@auth0/nextjs-auth0/client';

// Client SDK sends snake_case internally, you never see it
const authenticators = await mfa.getAuthenticators({ mfaToken });
const challenge = await mfa.challenge({ mfaToken, challengeType: 'otp' });
const result = await mfa.verify({ mfaToken, otp: '123456' });
```

### For Direct HTTP Callers

If you're making direct HTTP calls to the route handlers (not using the SDK), you MUST update your code.

#### Before: GET /auth/mfa/authenticators

```bash
# OLD (NO LONGER WORKS)
curl -X GET http://localhost:3000/auth/mfa/authenticators \
  -H "Content-Type: application/json" \
  -d '{"mfaToken": "encrypted_token"}'
```

#### After: GET /auth/mfa/authenticators

```bash
# NEW (Required)
curl -X GET http://localhost:3000/auth/mfa/authenticators \
  -H "Authorization: Bearer encrypted_token"
```

---

#### Before: POST /auth/mfa/challenge

```typescript
// OLD (NO LONGER WORKS)
const response = await fetch('/auth/mfa/challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    mfaToken: encryptedToken,
    challengeType: 'oob',
    authenticatorId: 'sms|dev_abc123'
  })
});
```

#### After: POST /auth/mfa/challenge

```typescript
// NEW (Required)
const response = await fetch('/auth/mfa/challenge', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${encryptedToken}`
  },
  body: JSON.stringify({
    mfa_token: encryptedToken,
    challenge_type: 'oob',
    authenticator_id: 'sms|dev_abc123'
  })
});
```

---

#### Before: POST /auth/mfa/associate

```typescript
// OLD (NO LONGER WORKS)
const response = await fetch('/auth/mfa/associate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    mfaToken: encryptedToken,
    authenticatorTypes: ['otp']
  })
});
```

#### After: POST /auth/mfa/associate

```typescript
// NEW (Required)
const response = await fetch('/auth/mfa/associate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${encryptedToken}`
  },
  body: JSON.stringify({
    authenticator_types: ['otp']
  })
});
```

---

#### Before: POST /auth/mfa/verify

```typescript
// OLD (NO LONGER WORKS)
const response = await fetch('/auth/mfa/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    mfaToken: encryptedToken,
    otp: '123456'
  })
});
```

#### After: POST /auth/mfa/verify

```typescript
// NEW (Required)
const response = await fetch('/auth/mfa/verify', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${encryptedToken}`
  },
  body: JSON.stringify({
    otp: '123456'
  })
});

// Parse response (snake_case)
const tokens = await response.json();
console.log(tokens.access_token);  // snake_case
console.log(tokens.refresh_token); // snake_case
console.log(tokens.expires_in);    // snake_case
```

---

#### Before: DELETE Authenticator (Unsupported)

```typescript
// This endpoint did not exist before
```

#### After: DELETE /auth/mfa/authenticators/{id}

```typescript
// NEW endpoint for deleting enrolled factors
const response = await fetch(
  `/auth/mfa/authenticators/${encodeURIComponent('sms|dev_abc123')}`,
  {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${encryptedToken}`
    }
  }
);

if (response.status === 204) {
  console.log('Authenticator deleted');
}
```

---

## Architecture: Transparent Proxy Pattern

### Design Goals

1. **Auth0 Compatibility:** Route handlers accept/return Auth0-shaped requests/responses
2. **SDK Transparency:** SDK users see no breaking changes (SDK types remain camelCase)
3. **Direct HTTP Support:** External systems can call route handlers directly with Auth0-shaped requests
4. **Security:** MFA tokens only via Authorization header (no query string exposure)

### Request Processing Flow

```
Request arrives at route handler
    ↓
Extract MFA token from Authorization header (ONLY)
    ↓
Parse JSON body (snake_case only)
    ↓
Validate snake_case field names
    ↓
Transform to SDK options (for business logic)
    ↓
Call AuthClient business method
    ↓
Get snake_case API response
    ↓
Return snake_case response to caller
```

### Response Processing Flow

```
AuthClient returns snake_case API response
    ↓
Route handler returns response AS-IS (no transformation)
    ↓
SDK client receives snake_case response
    ↓
Client SDK transforms to camelCase (via transform utils)
    ↓
Application receives camelCase SDK types
```

### Key Implementation Details

**Request Validation:**
- Authorization header extraction (mandatory)
- Request body field validation (snake_case only)
- No camelCase field name fallbacks
- Error responses include `error` and `error_description` fields

**Response Format:**
- All responses use snake_case field names
- Matches Auth0 API exactly
- SDK transforms to camelCase before returning to consumers

**Error Responses:**
```json
{
  "error": "<error_code>",
  "error_description": "<human_readable_message>",
  "mfa_token": "<optional_next_factor_token>"
}
```

---

## Special Cases & Details

### 1. Chained MFA (Multi-Factor)

When a user requires multiple factors (e.g., SMS then TOTP), Auth0 returns `mfa_required` with a new encrypted `mfa_token`:

```json
{
  "error": "mfa_required",
  "error_description": "Chained MFA required",
  "mfa_token": "<new_encrypted_token_for_next_factor>"
}
```

This is not an error — it means verification succeeded but another factor is required. The client receives this as a thrown `MfaRequiredError` with the new token.

### 2. Challenge Type Filtering

When retrieving authenticators or initiating challenges, the route handlers filter based on `mfa_requirements.challenge` from the original MFA token. Only challenge types allowed by Auth0 are returned.

If no challenge types are available:
```json
{
  "error": "mfa_no_available_factors",
  "error_description": "No MFA challenge types available in mfa_requirements"
}
```

### 3. OTP Enrollment: factorType → authenticator_types

The MFA API uses the field name `authenticator_types` (plural) which maps to an array of factor types:

```json
{
  "authenticator_types": ["otp"]
}
```

This is simpler than Auth0's legacy `factorType` field and explicitly indicates that multiple authenticator types can be enrolled simultaneously (though typically just one per request).

### 4. DELETE Authenticator Endpoint

New in this release. Removes an enrolled factor using the MFA token (same as other MFA endpoints):

```http
DELETE /auth/mfa/authenticators/{id}
Authorization: Bearer <mfa_token>
```

Returns 204 No Content on success.

---

## Testing Checklist

When upgrading, verify:

- [ ] SDK consumers see no breaking changes (camelCase still works in code)
- [ ] Direct HTTP callers get 400 errors with camelCase fields (old format rejected)
- [ ] All requests require Authorization header (query params no longer work)
- [ ] All responses use snake_case (verify field names in response JSON)
- [ ] Challenge endpoint accepts `mfa_token` in body (Auth0 compatibility)
- [ ] Verify endpoint returns tokens with snake_case fields
- [ ] DELETE endpoint returns 204 No Content
- [ ] Error responses use `error` and `error_description` (snake_case)
- [ ] Session cookies are set after verify (if session exists)
- [ ] Chained MFA works (mfa_required responses received correctly)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-12 | Initial BREAKING release - wire format alignment with Auth0 API |

---

## Support & Questions

For questions about this breaking change:

1. Check the [implementation plan](../impl-breaking-contract-parity-fix.md) for technical details
2. Review route handler source: `/src/server/auth-client.ts` (handlers) and `/src/server/mfa/server-mfa-client.ts` (business logic)
3. Review validation utilities: `/src/utils/mfa-validation-utils.ts`
4. Review transform utilities: `/src/utils/mfa-transform-utils.ts`

---
