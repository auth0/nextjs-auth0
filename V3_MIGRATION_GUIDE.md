# V3 Migration Guide

Guide to migrating from `2.x` to `3.x`

## Node 16 or newer is required

Node 16 LTS and newer LTS releases are supported.

## TypeScript changes

All the server functions of this SDK now support the App Router in addition to the Page Router.

As a result of this, the type signatures of these functions have been overloaded to include the App Router signatures.

So in some places, TypeScript may require help inferring the types of request and response. e.g.

### Before

```ts
import { withApiAuthRequired } from '@auth0/nextjs-auth0'

export default withApiAuthRequired(async function handler(req, res) {
  res.status(200).json({});
});
```

### After

```ts
import { NextApiRequest, NextApiResponse } from 'next';
import { withApiAuthRequired } from '@auth0/nextjs-auth0'

export default withApiAuthRequired(async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({});
});
```


## The `/401` handler has been removed

As of Next.js 13.1, you can now return responses from Middleware so the Unauthorized handler has been removed in favour of an Unauthorized response.

If you want to protect an API with `withMiddlewareAuthRequired` you will need a minimum of Next.js 13.1, or add the 401 back yourself. e.g.

```ts
import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth({
  '401'(_req, res) {
    res.status(401).json({
      error: 'not_authenticated',
      description: 'The user does not have an active session or is not authenticated'
    });
  }
});

```
