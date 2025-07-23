# Transaction Cookie Configuration Example

This example demonstrates how to configure transaction cookies in the Auth0 Next.js SDK to prevent cookie accumulation and manage authentication flows.

## Problem Solved

Prior to these configuration options, transaction cookies (`__txn_*`) would accumulate when users repeatedly navigated to protected routes or started multiple authentication flows. This could eventually cause HTTP 413 (Request Entity Too Large) errors when cookie headers exceeded server limits.

## Configuration Options

### Default Configuration (Parallel Transactions)

```typescript
// lib/auth0.ts
import { Auth0Client, TransactionStore } from "@auth0/nextjs-auth0/server";

// Default configuration - allows multiple parallel transactions
const transactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: true, // Default
  cookieOptions: {
    maxAge: 3600, // 1 hour (default)
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
});

export const auth0 = new Auth0Client({
  transactionStore,
  // ... other options
});
```

### Single Transaction Mode

```typescript
// lib/auth0-single-transaction.ts
import { Auth0Client, TransactionStore } from "@auth0/nextjs-auth0/server";

// Single transaction mode - prevents cookie accumulation
const transactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: false,
  cookieOptions: {
    maxAge: 1800, // 30 minutes
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
});

export const auth0 = new Auth0Client({
  transactionStore,
  // ... other options
});
```

### Custom Cookie Prefix and Settings

```typescript
// lib/auth0-custom.ts
import { Auth0Client, TransactionStore } from "@auth0/nextjs-auth0/server";

const transactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: true,
  cookieOptions: {
    prefix: "__myapp_auth_", // Custom prefix instead of __txn_
    maxAge: 2700, // 45 minutes
    sameSite: "strict",
    secure: true,
    path: "/app" // Limit to specific path
  }
});

export const auth0 = new Auth0Client({
  transactionStore,
  // ... other options
});
```

## When to Use Each Mode

### Parallel Transactions (Default)
✅ **Use when:**
- Users might open multiple tabs and log in simultaneously
- You want maximum compatibility with user behavior
- Your application supports concurrent authentication flows

### Single Transaction Mode
✅ **Use when:**
- You want to prevent cookie accumulation issues
- Users typically don't need multiple concurrent login flows
- You're experiencing cookie header size limits
- You prefer simpler transaction management

## Environment Variables

The basic Auth0 configuration still uses the same environment variables:

```env
# .env.local
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_SECRET=your-32-character-secret
APP_BASE_URL=http://localhost:3000
```

## Middleware Setup

The middleware setup remains the same regardless of transaction cookie configuration:

```typescript
// middleware.ts
import type { NextRequest } from "next/server";
import { auth0 } from "./lib/auth0"; // Use your configured auth0 instance

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)"
  ]
};
```

## Testing the Configuration

You can test your transaction cookie configuration by:

1. **Multi-tab testing**: Open multiple tabs and try logging in simultaneously
2. **Cookie inspection**: Check browser dev tools to see transaction cookies
3. **Abandoned flow testing**: Start login flows and navigate away to see cleanup

### Expected Cookie Behavior

**Parallel Mode:**
- Multiple `__txn_{state}` cookies during concurrent logins
- Automatic cleanup after successful authentication
- Cookies expire after `maxAge` seconds

**Single Mode:**
- Only one `__txn_` cookie at a time
- New logins replace existing transaction cookies
- Simpler cookie management

## Migration from Default Configuration

If you're experiencing cookie accumulation issues, you can migrate to single transaction mode:

```typescript
// Before (using defaults)
export const auth0 = new Auth0Client({
  // ... your existing config
});

// After (single transaction mode)
import { TransactionStore } from "@auth0/nextjs-auth0/server";

const transactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: false
});

export const auth0 = new Auth0Client({
  transactionStore,
  // ... your existing config
});
```

This change is backward compatible and won't affect existing user sessions.
