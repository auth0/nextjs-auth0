# Auth0 Next.js SDK - Pages Router Example

This example demonstrates using the Auth0 Next.js SDK with the **Pages Router** and **API Routes** instead of middleware.

## What This Example Shows

- **Pages Router**: Traditional Next.js routing with the `pages/` directory
- **API Route Mounting**: Authentication routes mounted via catch-all API routes
- **Server-Side Props**: Session data fetched using `getServerSideProps`
- **No Middleware**: Authentication doesn't use Next.js middleware

## Key Differences

| Feature | App Router | Pages Router (This Example) |
|---------|------------|----------------------------|
| Directory Structure | `app/` | `pages/` |
| API Routes | `app/api/[...auth0]/route.ts` | `pages/api/[...auth0].ts` |
| Server Data Fetching | `async` components | `getServerSideProps` |
| Layout | `layout.tsx` | `_app.tsx` + `_document.tsx` |
| Protected Routes | `redirect()` in component | Redirect in `getServerSideProps` |

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
- **Allowed Callback URLs**: `http://localhost:3000/api/auth/callback`
- **Allowed Logout URLs**: `http://localhost:3000`

4. **Run the development server:**

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to see the app.

## Project Structure

```
with-pages-router/
├── pages/
│   ├── api/
│   │   └── [...auth0].ts          # Auth routes handler (key file!)
│   ├── _app.tsx                   # App wrapper
│   ├── _document.tsx              # HTML document structure
│   ├── index.tsx                  # Public home page
│   └── profile.tsx                # Protected page example
├── lib/
│   └── auth0.ts                   # Auth0 client config
├── styles/
│   └── globals.css                # Global styles
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
  }
});
```

### `pages/api/[...auth0].ts` - Route Handler

```typescript
import { auth0 } from "@/lib/auth0";
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  return auth0.apiRoute(req, res);
}
```

### `pages/index.tsx` - Home Page with Server-Side Props

```typescript
import { auth0 } from "@/lib/auth0";
import { GetServerSideProps } from "next";

export default function Home({ session }) {
  // ... component code
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  const session = await auth0.getSession(context.req, context.res);

  return {
    props: { session }
  };
};
```

### `pages/profile.tsx` - Protected Page

```typescript
export const getServerSideProps: GetServerSideProps = async (context) => {
  const session = await auth0.getSession(context.req, context.res);

  if (!session) {
    return {
      redirect: {
        destination: "/api/auth/login",
        permanent: false
      }
    };
  }

  return {
    props: { session }
  };
};
```

## Available Routes

With this setup, the following routes are automatically available:

- `/api/auth/login` - Initiates login
- `/api/auth/logout` - Logs out the user
- `/api/auth/callback` - OAuth callback handler
- `/api/auth/profile` - Returns user profile JSON

## Pages Router vs App Router

**Use Pages Router when:**
- Working with an existing Pages Router codebase
- You prefer traditional Next.js routing patterns
- You need `getServerSideProps` or `getStaticProps`

**Use App Router when:**
- Starting a new project (Next.js 13+ recommendation)
- You want React Server Components
- You prefer modern Next.js patterns

Both routers work equally well with Auth0!

## Learn More

- [Auth0 Next.js SDK Documentation](https://github.com/auth0/nextjs-auth0)
- [Next.js Pages Router Documentation](https://nextjs.org/docs/pages)
- [Next.js API Routes](https://nextjs.org/docs/pages/building-your-application/routing/api-routes)

## Migrating to App Router

If you want to migrate this example to the App Router:

1. Rename `pages/` to `app/`
2. Convert `pages/api/[...auth0].ts` to `app/api/[...auth0]/route.ts`
3. Replace `getServerSideProps` with async component functions
4. Replace `_app.tsx` with `layout.tsx`
5. Update imports and exports accordingly

Check out the `with-api-routes` example to see the App Router version!
