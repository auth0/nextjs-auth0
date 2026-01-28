# MFA Testing Example

A comprehensive Next.js application demonstrating Auth0 MFA (Multi-Factor Authentication) step-up flows using `@auth0/nextjs-auth0`.

## Features

- **Step-up MFA**: MFA triggered only when accessing protected resources (not at login)
- **Multiple Authenticator Types**: OTP/TOTP, SMS, Email
- **Factor Management**: Enroll, list, and delete authenticators
- **Verbose Logging**: Real-time log viewer for debugging
- **Error Handling**: Graceful recovery from invalid codes, expired tokens
- **Token Caching**: Automatic caching to avoid repeated MFA prompts

## User Journeys

### Act 1: First-Time User
1. Login without MFA → Dashboard
2. Access protected API → MFA enrollment required
3. Enroll OTP authenticator → Scan QR code
4. Verify enrollment → Enter OTP code
5. Access granted → Protected data displayed

### Act 2: Returning User
6. Login again → Dashboard (no MFA at login!)
7. Access protected API → MFA challenge
8. Verify quickly → Enter OTP
9. Subsequent calls → Cached token (no MFA)

### Act 3: Factor Management
10. Enroll second factor → SMS
11. View all factors → Manage screen
12. Delete factor → Confirmation

### Act 4: Error Handling
13. Invalid OTP → Retry
14. Token expiration → Auto-recovery

## Setup

1. **Install dependencies**:
   ```bash
   pnpm install
   ```

2. **Configure Auth0**:
   - Create Regular Web Application
   - Enable MFA authenticators (OTP, SMS, Email)
   - Deploy MFA step-up action for `resource-server-1`
   - Enable tenant flag: `mfa_list_with_challenge_type`

3. **Environment variables** (`.env.local`):
   ```bash
   AUTH0_DOMAIN=your-tenant.auth0.com
   AUTH0_CLIENT_ID=your-client-id
   AUTH0_CLIENT_SECRET=your-client-secret
   AUTH0_ISSUER_BASE_URL=https://your-tenant.auth0.com
   AUTH0_SECRET=random-32-char-secret
   APP_BASE_URL=http://localhost:3000
   AUTH0_AUDIENCE=resource-server-1
   ```
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your Auth0 credentials
   ```

4. **Run development server**:
   ```bash
   pnpm dev
   ```

5. **Open browser**: http://localhost:3000

## Configuration Notes

### Step-up MFA Pattern

For step-up MFA, **do not** include `audience` in SDK initialization:

```typescript
// ✅ Correct - Step-up MFA
export const auth0 = new Auth0Client();
// MFA triggered on-demand via getAccessToken({ audience })

// ❌ Wrong - Triggers MFA at login (Universal Login flow)
export const auth0 = new Auth0Client({
  authorizationParameters: { audience: 'resource-server-1' }
});
```

MFA is triggered when requesting protected audience:

```typescript
// This triggers the MFA step-up flow
const token = await auth0.getAccessToken({
  audience: 'resource-server-1'
});
```

The SDK internally uses `refresh_token` grant to request the new audience, which activates the MFA action.

## Architecture

```
app/
├── layout.tsx                  # Root layout
├── page.tsx                    # Home (logged out)
├── dashboard/
│   └── page.tsx                # User dashboard
├── mfa/
│   ├── enroll/
│   │   ├── page.tsx            # Enrollment router
│   │   ├── otp/page.tsx        # OTP enrollment
│   │   ├── sms/page.tsx        # SMS enrollment
│   │   └── email/page.tsx      # Email enrollment
│   ├── challenge/
│   │   └── page.tsx            # Challenge + Verify
│   └── manage/
│       └── page.tsx            # Factor management
└── api/
    └── protected/
        └── route.ts             # Protected API endpoint

components/
├── mfa/
│   ├── authenticator-list.tsx   # Factor picker
│   ├── qr-code-display.tsx      # QR code renderer
│   ├── recovery-codes.tsx       # Recovery codes display
│   ├── otp-input.tsx            # 6-digit OTP input
│   └── error-display.tsx        # Error banners
├── log-viewer.tsx               # Real-time logs
├── user-info.tsx                # User details panel
└── protected-data.tsx           # Protected content display

lib/
├── auth0.ts                     # Auth0Client config
├── types.ts                     # MFA types
└── mfa-logger.ts                # Verbose logging
```

## Logging

The app includes comprehensive verbose logging for debugging:

- All MFA operations logged with `[MFA]` prefix
- Token details (length, expiry, audience)
- Error details (code, description, recovery)
- Real-time log viewer component (collapsible panel)

Enable verbose logs in components by importing:
```typescript
import { mfaLog } from '@/lib/mfa-logger';

mfaLog.info('User selected factor type:', factorType);
mfaLog.error('Verification failed:', error);
```

## Demo Script

Perfect for executive presentations showcasing the MFA flow:

1. **Setup**: Clean user account, no MFA enrolled
2. **Act 1** (5 min): First-time enrollment flow
3. **Act 2** (2 min): Returning user fast path
4. **Act 3** (2 min): Factor management (optional)
5. **Act 4** (1 min): Error handling (optional)

**Total**: 10 minutes for full demo

## Troubleshooting

### MFA Triggered at Login
- Remove `audience` from SDK init in `lib/auth0.ts`
- Ensure action only triggers on `refresh_token` grant

### No MFA Required Error
- Verify action is deployed and active
- Check action targets correct audience (`resource-server-1`)
- Confirm tenant flag `mfa_list_with_challenge_type` is enabled

### Invalid Token
- Check token encryption/decryption
- Verify token TTL (default 5 minutes)
- Ensure MFA token passed correctly between flows

## License

MIT
