---
name: nextjs-auth0
description: >-
  Add authentication to Next.js applications using @auth0/nextjs-auth0 v4
  (App Router + Pages Router): install, Auth0Client singleton, middleware/proxy
  route mounting, env config, useUser, getSession/getAccessToken, protecting
  pages and API routes, and step-up MFA. Entry point for all nextjs-auth0 skills.
metadata:
  type: core
  library: nextjs-auth0
  library_version: 4.30.0
---

# Auth0 Next.js Integration

Add authentication to Next.js applications using @auth0/nextjs-auth0. Supports both App Router and Pages Router.

## Sub-skills

| Task | Sub-skill |
|------|-----------|
| Step-up auth, `mfa_required`, enroll/challenge/verify, popup or redirect step-up | [mfa/SKILL.md](./mfa/SKILL.md) |
| Multi-tenant B2B, pass `organization` at login, read `org_id`, invitations, org/connection setup | [organizations/SKILL.md](./organizations/SKILL.md) |
| Passkey signup, sign-in, and My Account enrollment using the server-side `auth0.passkey.*` API | [passkeys/SKILL.md](./passkeys/SKILL.md) |

## Prerequisites

- Next.js 14.2.35+ application (App Router or Pages Router)
- Auth0 account and application configured
- If Auth0 isn't set up yet, set it up first with the Auth0 CLI (`auth0 login`, then `auth0 apps create`)

## When NOT to Use

- **Client-side only React apps** - Use the Auth0 integration workflow for React (Vite/CRA SPAs)
- **React Native mobile apps** - Use the Auth0 integration workflow for React Native (iOS/Android)
- **Non-Next.js frameworks** - Use framework-specific SDKs (Express, Vue, Angular, etc.)
- **Stateless APIs only** - Use JWT validation middleware if you don't need session management

## Quick Start Workflow

### 1. Install SDK

```bash
npm install @auth0/nextjs-auth0
```

### 2. Configure Environment

**For automated setup with Auth0 CLI**, see the Setup Guide section below for complete scripts.

**For manual setup:**

Create `.env.local`:

```bash
AUTH0_SECRET=<generate-a-32-character-secret>
APP_BASE_URL=http://localhost:3000
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
```

Generate secret: `openssl rand -hex 32`

**Important:** Add `.env.local` to `.gitignore`

### 3. Create Auth0 Client and Middleware

**Detect project structure first:** Check whether the project uses a `src/` directory (i.e. `src/app/` or `src/pages/` exists). This determines where to place files:
- **With `src/`:** `src/lib/auth0.ts`, `src/middleware.ts` (or `src/proxy.ts` for Next.js 16)
- **Without `src/`:** `lib/auth0.ts`, `middleware.ts` (or `proxy.ts` for Next.js 16)

Create `lib/auth0.ts` (or `src/lib/auth0.ts` if using the `src/` convention):

```typescript
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  secret: process.env.AUTH0_SECRET!,
  appBaseUrl: process.env.APP_BASE_URL!,
});
```

**Middleware Configuration (Next.js 15 vs 16):**

**Next.js 15** - Create `middleware.ts` (at project root, or `src/middleware.ts` if using `src/`):

```typescript
import { NextRequest } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function middleware(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
};
```

**Next.js 16** - You have two options:

**Option 1:** Use `middleware.ts` (same as Next.js 15, same `src/` placement rules).

**Option 2:** Use `proxy.ts` (at project root, or `src/proxy.ts` if using `src/`):

```typescript
import { NextRequest } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function proxy(request: NextRequest) {
  return await auth0.middleware(request);
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
};
```

This automatically creates endpoints:
- `/auth/login` - Login
- `/auth/logout` - Logout
- `/auth/callback` - OAuth callback
- `/auth/profile` - User profile

### 4. Add User Context (Optional)

**Note:** In v4, wrapping with `<Auth0Provider>` is optional. Only needed if you want to pass an initial user during server rendering to `useUser()`.

**App Router** - Optionally wrap app in `app/layout.tsx`:

```typescript
import { Auth0Provider } from '@auth0/nextjs-auth0/client';
import { auth0 } from '@/lib/auth0';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await auth0.getSession();

  return (
    <html>
      <body>
        <Auth0Provider user={session?.user}>{children}</Auth0Provider>
      </body>
    </html>
  );
}
```

**Pages Router** - Optionally wrap app in `pages/_app.tsx`:

```typescript
import { Auth0Provider } from '@auth0/nextjs-auth0/client';
import type { AppProps } from 'next/app';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <Auth0Provider user={pageProps.user}>
      <Component {...pageProps} />
    </Auth0Provider>
  );
}
```

### 5. Add Authentication UI

**Client Component** (works in both routers):

```typescript
'use client'; // Only needed for App Router

import { useUser } from '@auth0/nextjs-auth0/client';

export default function Profile() {
  const { user, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;

  if (user) {
    return (
      <div>
        <img src={user.picture} alt={user.name} />
        <h2>Welcome, {user.name}!</h2>
        <a href="/auth/logout">Logout</a>
      </div>
    );
  }

  return <a href="/auth/login">Login</a>;
}
```

### 6. Test Authentication

Start your dev server:

```bash
npm run dev
```

Visit `http://localhost:3000` and test the login flow.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Using v3 environment variables | v4 uses `APP_BASE_URL` and `AUTH0_DOMAIN` (not `AUTH0_BASE_URL` or `AUTH0_ISSUER_BASE_URL`) |
| Forgot to add callback URL in Auth0 Dashboard | Add `/auth/callback` to Allowed Callback URLs (e.g., `http://localhost:3000/auth/callback`) |
| Missing middleware configuration | v4 requires middleware to mount auth routes - create `middleware.ts` (Next.js 15+16) or `proxy.ts` (Next.js 16 only) with `auth0.middleware()` |
| Wrong route paths | v4 uses `/auth/login` not `/api/auth/login` - routes drop the `/api` prefix |
| Missing or weak AUTH0_SECRET | Generate secure secret with `openssl rand -hex 32` and store in .env.local |
| Using .env instead of .env.local | Next.js requires .env.local for local secrets, and .env.local should be in .gitignore |
| App created as SPA type in Auth0 | Must be Regular Web Application type for Next.js |
| Using standalone `withPageAuthRequired` / `withApiAuthRequired` | Use the instance methods `auth0.withPageAuthRequired()` and `auth0.withApiAuthRequired()`, or `auth0.getSession()` directly |
| Using useUser in Server Component | useUser is client-only, use `auth0.getSession()` for Server Components |
| AUTH0_DOMAIN includes https:// | v4 `AUTH0_DOMAIN` should be just the domain (e.g., `example.auth0.com`), no scheme |

## Related Capabilities

- Auth0 setup — run the Auth0 CLI (`auth0 login`, then `auth0 apps create`)
- Multi-factor authentication → [mfa/SKILL.md](./mfa/SKILL.md)
- Multi-tenant B2B / Organizations → [organizations/SKILL.md](./organizations/SKILL.md)
- Managing Auth0 resources from the terminal → the Auth0 CLI

## Quick Reference

**V4 Setup:**
- Detect `src/` convention: check if `src/app/` or `src/pages/` exists — place all files inside `src/` if so
- Create `lib/auth0.ts` (or `src/lib/auth0.ts`) with `Auth0Client` instance
- Create middleware configuration (required):
  - Next.js 15: `middleware.ts` (or `src/middleware.ts`) with `middleware()` function
  - Next.js 16: `middleware.ts` with `middleware()` OR `proxy.ts` with `proxy()` function (same `src/` rules)
- Optional: Wrap with `<Auth0Provider>` for SSR user

**Client-Side Hooks:**
- `useUser()` - Get user in client components
- `user` - User profile object
- `isLoading` - Loading state

**Server-Side Methods:**
- `auth0.getSession()` - Get session in Server Components/API routes/middleware
- `auth0.getAccessToken()` - Get access token for calling APIs

## Common Patterns

### Custom Login with Options

```typescript
<a href="/auth/login?returnTo=/dashboard">
  Login and go to Dashboard
</a>
```

Or programmatically:

```typescript
const router = useRouter();
router.push('/auth/login?returnTo=/dashboard');
```

### Get Access Token for External APIs

```typescript
import { auth0 } from '@/lib/auth0';
import { NextResponse } from 'next/server';

export async function GET() {
  const { token } = await auth0.getAccessToken();

  if (!token) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  const apiResponse = await fetch('https://api.example.com/data', {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return NextResponse.json(await apiResponse.json());
}
```

### Silent Authentication

Users remain logged in across sessions automatically with refresh tokens.

To force re-authentication:

```typescript
<a href="/auth/login?prompt=login">
  Force Re-login
</a>
```

## Configuration Options

### Advanced Auth0 Configuration

```typescript
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  secret: process.env.AUTH0_SECRET!,
  appBaseUrl: process.env.APP_BASE_URL!,
  authorizationParameters: {
    scope: 'openid profile email',
    audience: process.env.AUTH0_AUDIENCE,
  },
  routes: {
    login: '/auth/login',
    callback: '/auth/callback',
    logout: '/auth/logout',
    profile: '/auth/profile',
  },
  session: {
    rolling: true,
    inactivityDuration: 24 * 60 * 60, // 24 hours in seconds
    absoluteDuration: 7 * 24 * 60 * 60, // 7 days in seconds
  },
});
```

**Note:** Most configuration can be omitted - v4 uses sensible defaults. The middleware automatically mounts auth routes.

## Integration Patterns

Server-side and client-side auth patterns for both App and Pages Router.

### Protected Pages

**App Router - Server Component**

```typescript
// app/profile/page.tsx
import { auth0 } from '@/lib/auth0';
import { redirect } from 'next/navigation';

export default async function Profile() {
  // In App Router, getSession() reads the request/response from Next.js' async context,
  // so you don't pass req/res like in the Pages Router example below.
  const session = await auth0.getSession();

  if (!session) {
    redirect('/auth/login?returnTo=/profile');
  }

  return (
    <div>
      <h1>Welcome, {session.user.name}!</h1>
      <img src={session.user.picture} alt={session.user.name} />
    </div>
  );
}
```

**Pages Router - SSR**

```typescript
// pages/profile.tsx
import { auth0 } from '@/lib/auth0';
import { GetServerSideProps } from 'next';

export default function Profile({ user }: { user: any }) {
  return <h1>Welcome, {user.name}!</h1>;
}

export const getServerSideProps: GetServerSideProps = async ({ req }) => {
  const session = await auth0.getSession(req);

  if (!session) {
    return {
      redirect: {
        destination: '/auth/login?returnTo=/profile',
        permanent: false,
      },
    };
  }

  return {
    props: { user: session.user },
  };
};
```

### Protected API Routes

**App Router**

```typescript
// app/api/private/route.ts
import { auth0 } from '@/lib/auth0';
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const session = await auth0.getSession();

  if (!session) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  return NextResponse.json({ data: 'Protected data', user: session.user });
}
```

**Pages Router**

```typescript
// pages/api/private.ts
import { auth0 } from '@/lib/auth0';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await auth0.getSession(req);

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  res.json({ user: session.user });
}
```

### Middleware Protection

Protect multiple routes with middleware.

**File placement:** If the project uses a `src/` directory (i.e. `src/app/` exists), place `middleware.ts` or `proxy.ts` inside `src/`. Otherwise, place at the project root.

**Next.js 15** - Use `middleware.ts` (or `src/middleware.ts`):

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function middleware(request: NextRequest) {
  const authRes = await auth0.middleware(request);

  // Allow auth routes to be handled by SDK
  if (request.nextUrl.pathname.startsWith('/auth')) {
    return authRes;
  }

  // Public routes
  if (request.nextUrl.pathname === '/') {
    return authRes;
  }

  // Protected routes - check session
  const session = await auth0.getSession(request);

  if (!session) {
    const { origin } = new URL(request.url);
    return NextResponse.redirect(`${origin}/auth/login?returnTo=${request.nextUrl.pathname}`);
  }

  return authRes;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)',
  ],
};
```

**Next.js 16** - Use either `middleware.ts` (same as above) or `proxy.ts` with a `proxy()` export (same `src/` placement rules).

### Calling External APIs

**App Router - Server Action**

```typescript
// app/actions.ts
'use server';

import { auth0 } from '@/lib/auth0';

export async function getData() {
  const { token } = await auth0.getAccessToken();

  if (!token) {
    throw new Error('No access token available');
  }

  const response = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${token}` }
  });

  return response.json();
}
```

**Pages Router - API Route**

```typescript
// pages/api/data.ts
import { auth0 } from '@/lib/auth0';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await auth0.getSession(req);

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { token } = await auth0.getAccessToken(req, res);

  if (!token) {
    return res.status(401).json({ error: 'No access token' });
  }

  const response = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await response.json();
  res.json(data);
}
```

## Testing

1. Start your dev server: `npm run dev`
2. Visit `http://localhost:3000`
3. Click "Login" - redirects to Auth0
4. Complete authentication
5. Verify redirect back with user session
6. Test protected pages and API routes
7. Click "Logout" and verify session cleared

## Common Issues

| Issue | Solution |
|-------|----------|
| "Missing required parameter: redirect_uri" | Ensure `APP_BASE_URL` is set correctly (v4 renamed from `AUTH0_BASE_URL`) |
| "Invalid state" error | Clear cookies/storage. Verify callback URL in Auth0 dashboard matches `APP_BASE_URL/auth/callback` |
| User session not persisting | Check `AUTH0_SECRET` is set and at least 32 characters |
| API routes return 401 | Check session with `auth0.getSession()` in route handler |
| Middleware loops infinitely | Do not exclude `/auth/*` from the matcher — those routes must reach `auth0.middleware()`. Instead return `authRes` early when `request.nextUrl.pathname.startsWith('/auth')` |
| Import errors for `withApiAuthRequired` / `withPageAuthRequired` | These are instance methods — use `auth0.withApiAuthRequired()` / `auth0.withPageAuthRequired()`, or `auth0.getSession()` directly |
| Environment variable not recognized | v4 uses `AUTH0_DOMAIN` (no scheme) and `APP_BASE_URL`, not `AUTH0_ISSUER_BASE_URL` or `AUTH0_BASE_URL` |
| Callback URL mismatch | Add `/auth/callback` to Allowed Callback URLs (v4 dropped `/api` prefix) |
| Routes return 404 | v4 uses `/auth/*` paths, not `/api/auth/*` - update all auth links |

## Security Considerations

- **Keep secrets secure** - Never commit `.env.local` to version control
- **Use HTTPS in production** - Auth0 requires secure callback URLs
- **Rotate secrets regularly** - Update `AUTH0_SECRET` periodically
- **Validate on server** - Always verify authentication server-side, not client-side
- **Configure CORS** - Set allowed origins in Auth0 application settings

## Setup Guide (Auth0 CLI)

### Quick Setup (Automated)

**Never read the contents of `.env.local` or `.env` at any point during setup.** The file may contain sensitive secrets that should not be exposed in the LLM context. If you determine you need to read the file for any reason, ask the user for explicit permission before doing so — do not proceed until the user confirms.

**Before running any part of this setup that writes to an env file, you MUST ask the user for explicit confirmation.** Follow the steps below precisely.

#### Step 1: Check for existing env files and confirm with user

Before writing credentials, check which env files exist:

```bash
test -f .env.local && echo "ENV_LOCAL_EXISTS" || echo "ENV_LOCAL_NOT_FOUND"
test -f .env && echo "ENV_EXISTS" || echo "ENV_NOT_FOUND"
```

Then ask the user for explicit confirmation before proceeding — do not continue until the user confirms:

- If `.env.local` exists, ask whether to append Auth0 credentials to it (it may contain unrelated secrets; the setup appends without modifying existing content).
- If `.env.local` does **not** exist but `.env` exists, ask the same about `.env`.
- If neither exists, ask whether to create `.env.local` with Auth0 credentials and a placeholder for `AUTH0_CLIENT_SECRET`.

**Do not proceed with writing to any env file unless the user selects the confirmation option.**

#### Step 2: Run automated setup (only after confirmation)

```bash
#!/bin/bash

# Install Auth0 CLI
if ! command -v auth0 &> /dev/null; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install auth0
  else
    INSTALLER=$(mktemp)
    curl -sSfL https://raw.githubusercontent.com/auth0/auth0-cli/main/install.sh -o "$INSTALLER"
    mkdir -p "$HOME/.local/bin" && sh "$INSTALLER" -b "$HOME/.local/bin"
    export PATH="$HOME/.local/bin:$PATH"
    rm -f "$INSTALLER"
  fi
fi

# Require jq for JSON parsing
if ! command -v jq &> /dev/null; then
  echo "Error: jq is required. Install it first (e.g. apt install jq / brew install jq)." >&2
  exit 1
fi

# Login
if ! auth0 tenants list &> /dev/null; then
  echo "Visit https://auth0.com/signup if you need an account"
  auth0 login
fi

# Create/select app
auth0 apps list
read -p "Enter app ID (or Enter to create new): " APP_ID

if [ -z "$APP_ID" ]; then
  APP_ID=$(auth0 apps create \
    --name "${PWD##*/}-nextjs" \
    --type regular \
    --callbacks "http://localhost:3000/auth/callback" \
    --logout-urls "http://localhost:3000" \
    --metadata "created_by=agent_skills" \
    --json | jq -r '.client_id')
fi

# Get credentials
APP_JSON=$(auth0 apps show "$APP_ID" --json)
AUTH0_DOMAIN=$(echo "$APP_JSON" | jq -r '.domain // empty')
AUTH0_CLIENT_ID=$(echo "$APP_JSON" | jq -r '.client_id // empty')

if [ -z "$AUTH0_DOMAIN" ] || [ -z "$AUTH0_CLIENT_ID" ]; then
  echo "Error: failed to retrieve app credentials. Check the app ID and try again." >&2
  exit 1
fi

# Generate secret
AUTH0_SECRET=$(openssl rand -hex 32)

# Determine target env file
if [ -f .env.local ]; then
  TARGET_FILE=".env.local"
elif [ -f .env ]; then
  TARGET_FILE=".env"
else
  TARGET_FILE=".env.local"
fi

# Append Auth0 credentials
cat >> "$TARGET_FILE" << ENVEOF
AUTH0_SECRET=$AUTH0_SECRET
APP_BASE_URL=http://localhost:3000
AUTH0_DOMAIN=$AUTH0_DOMAIN
AUTH0_CLIENT_ID=$AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET='YOUR_CLIENT_SECRET'
ENVEOF

echo "✅ Auth0 credentials written to $TARGET_FILE"
```

After the script runs, remind the user to:
1. Open the env file that was written and replace `YOUR_CLIENT_SECRET` with the actual client secret from Auth0.
2. Ensure the env file is listed in `.gitignore` to avoid accidentally committing secrets.

### Manual Setup

Install the SDK (`npm install @auth0/nextjs-auth0`), create `.env.local` with the five variables above (generate `AUTH0_SECRET` with `openssl rand -hex 32`), then configure the Auth0 Application as a **Regular Web Application** with Allowed Callback URL `http://localhost:3000/auth/callback` and Allowed Logout URL `http://localhost:3000` — via the CLI (`auth0 login`, `auth0 apps create --type regular ...`) or the dashboard.

## References

- [Auth0 Next.js SDK Documentation](https://auth0.com/docs/libraries/nextjs-auth0)
- [Auth0 Next.js SDK GitHub](https://github.com/auth0/nextjs-auth0)
- [Auth0 Next.js Quickstart](https://auth0.com/docs/quickstart/webapp/nextjs)
- [Next.js Middleware Documentation](https://nextjs.org/docs/app/building-your-application/routing/middleware)

## Version note

Targets `@auth0/nextjs-auth0` v4.30.0. See the `V*_MIGRATION_GUIDE.md` files for older APIs. The MFA **management** API is Early Access.
