# Auth0 Next.js SDK - API Routes Example

This example demonstrates using the Auth0 Next.js SDK with **API Routes** instead of middleware, following Next.js's current recommendations.

## What This Example Shows

- **API Route Mounting**: Authentication routes mounted via catch-all API routes instead of middleware
- **Both Routers**: Demonstrates the pattern for App Router (primary example)

## Key Differences from Middleware Approach

| Feature | Middleware (Default) | API Routes (This Example) |
|---------|---------------------|---------------------------|
| Route Mounting | Via `middleware.ts` | Via `app/api/auth/[...auth0]/route.ts` |
| Session Rolling | Automatic on every request | Only when auth routes are called |
| Setup Files | 1 file (middleware.ts) | 2 files (config + API route) |
| Next.js Alignment | Works but not recommended | Recommended by Next.js |

## Setup

1. **Install dependencies:**

```bash
npm install
```

2. **Configure environment variables:**

Create a `.env.local` file:

```env
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_SECRET=use-openssl-rand-hex-32-to-generate
APP_BASE_URL=http://localhost:3000
```

3. **Configure Auth0 Application:**

In your Auth0 Dashboard, add these URLs to your application:
- **Allowed Callback URLs**: `http://localhost:3000/auth/callback`
- **Allowed Logout URLs**: `http://localhost:3000`

4. **Run the development server:**

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to see the app.

## Project Structure

```
with-api-routes/
├── app/
│   ├── api/
│   │   └── [...auth0]/
│   │       └── route.ts           # Auth routes handler (key file!)
│   ├── profile/
│   │   └── page.tsx               # Protected page example
│   ├── layout.tsx                 # Root layout
│   └── page.tsx                   # Public home page
├── lib/
│   └── auth0.ts                   # Auth0 client config
└── package.json
```

## Key Files

### `lib/auth0.ts` - Configuration

```typescript
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  routes: {
    login: "/api/auth/login",
    logout: "/api/auth/logout",
    callback: "/api/auth/callback"
  },
});
```

### `app/api/[...auth0]/route.ts` - Route Handler

```typescript
import { auth0 } from "@/lib/auth0";

export const GET = auth0.apiRoute;
export const POST = auth0.apiRoute;
```

That's it! Just 3 lines to mount all authentication routes.

## Available Routes

With this setup, the following routes are automatically available:

- `/auth/login` - Initiates login
- `/auth/logout` - Logs out the user
- `/auth/callback` - OAuth callback handler
- `/auth/profile` - Returns user profile JSON

## Learn More

- [Auth0 Next.js SDK Documentation](https://github.com/auth0/nextjs-auth0)
- [API Routes vs Middleware Guide](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#using-api-routes-instead-of-middleware)
- [Next.js API Routes](https://nextjs.org/docs/app/building-your-application/routing/route-handlers)

## Migrating from Middleware

If you have an existing app using middleware, migration is simple:

1. Create `app/api/auth/[...auth0]/route.ts` with the handler
2. Remove or update `middleware.ts` (if only used for auth)

No other code changes needed!
