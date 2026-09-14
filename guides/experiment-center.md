# Experiment Center

[Experiment Center](https://auth0.com/docs/customize/experiment-center/overview) is Auth0's A/B testing platform for login flows. Auth0 assigns each user to a variant server-side. You can override that assignment for a specific request by passing `experiment_id` and `variation_id` on the login call.

> **Note:** Experiment Center is an Enterprise feature currently in Early Access. Contact your Auth0 representative to request access.

[Back to EXAMPLES.md](../EXAMPLES.md)

## Forcing a variant

Pass `experiment_id` and `variation_id` via `authorizationParameters` on a per-call basis. The override applies to that request only -- the next login without these params reverts to normal server-side assignment.

```ts
// app/api/auth/login/route.ts
import { auth0 } from "@/lib/auth0";

export const GET = auth0.handleLogin({
  authorizationParameters: {
    experiment_id: "<EXPERIMENT_ID>",
    variation_id: "<VARIATION_ID>"
  }
});
```

When the experiment uses segment targeting, also pass `segment_id`:

```ts
export const GET = auth0.handleLogin({
  authorizationParameters: {
    experiment_id: "<EXPERIMENT_ID>",
    variation_id: "<VARIATION_ID>",
    segment_id: "<SEGMENT_ID>"
  }
});
```

Pass these **per-call** rather than in `authorizationParameters` at client construction time, so the override does not affect silent `prompt=none` token-renewal calls (Experiment Center does not run on those).

## Callers

**For testing:** drive from test automation (e.g. Cypress, Playwright) with IDs read from a CI environment variable against a development tenant. Do not hard-code variant IDs in shipped application code.

**For production:** pass the variant decision from a feature-flag tool (e.g. LaunchDarkly) that has already decided which variant the user should see for this request.
