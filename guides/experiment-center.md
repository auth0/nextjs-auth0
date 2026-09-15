# Experiment Center

[Experiment Center](https://auth0.com/docs/customize/experiment-center/overview) is Auth0's A/B testing platform for login flows. Auth0 assigns each user to a variant server-side. You can override that assignment for a specific login by passing `experiment_id` and `variation_id` as authorization parameters.

> **Note:** Experiment Center is an Enterprise feature currently in Early Access. Contact your Auth0 representative to request access.

[Back to EXAMPLES.md](../EXAMPLES.md)

## Forcing a variant

Pass `experiment_id` and `variation_id` on a per-login basis. The override applies to that login only -- the next login without these params reverts to normal server-side assignment.

The simplest option is to add them as query parameters on the `/auth/login` route:

```html
<a href="/auth/login?experiment_id=<EXPERIMENT_ID>&variation_id=<VARIATION_ID>">
  Log in
</a>
```

If you start the login programmatically, pass them through `authorizationParameters` on `startInteractiveLogin`:

```ts
// app/api/experiment-login/route.ts
import { NextRequest } from "next/server";

import { auth0 } from "@/lib/auth0";

export const GET = async (req: NextRequest) => {
  return auth0.startInteractiveLogin({
    authorizationParameters: {
      experiment_id: "<EXPERIMENT_ID>",
      variation_id: "<VARIATION_ID>"
    }
  });
};
```

When the experiment uses segment targeting, also pass `segment_id`:

```ts
export const GET = async (req: NextRequest) => {
  return auth0.startInteractiveLogin({
    authorizationParameters: {
      experiment_id: "<EXPERIMENT_ID>",
      variation_id: "<VARIATION_ID>",
      segment_id: "<SEGMENT_ID>"
    }
  });
};
```

Pass these **per-login** rather than in `authorizationParameters` at client construction time. Setting them on the client applies the override to every login the SDK starts, so you would no longer be A/B testing -- every user would be pinned to the same variant.

## Callers

**For testing:** drive from test automation (e.g. Cypress, Playwright) with IDs read from a CI environment variable against a staging tenant. Do not hard-code variant IDs in shipped application code.

**For production:** pass the variant decision from a feature-flag tool (e.g. LaunchDarkly) that has already decided which variant the user should see for this login.
