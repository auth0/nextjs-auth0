# My Account API

Examples for calling the [Auth0 My Account API](https://auth0.com/docs/manage-users/my-account-api) from your Next.js application with the Auth0 Next.js SDK. This covers the built-in `/me` proxy, managing the user's profile, and integration with Auth0 UI Components.

For how the proxy works in general (supported HTTP methods, CORS, token management, and security considerations), see [Proxy Handler for My Account and My Organization APIs](../EXAMPLES.md#proxy-handler-for-my-account-and-my-organization-apis).

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [My Account API Proxy](#my-account-api-proxy)
  - [Configuration](#configuration)
  - [Client-Side Usage](#client-side-usage)
  - [`scope` Header](#scope-header)
- [Managing the User Profile](#managing-the-user-profile)
  - [Auth0 Setup](#auth0-setup)
  - [Reading the Profile](#reading-the-profile)
  - [Updating Attributes](#updating-attributes)
  - [Calling the API from the Server](#calling-the-api-from-the-server)
  - [Error Handling](#error-handling)
  - [Limitations](#limitations)
- [Integration with UI Components](#integration-with-ui-components)

## My Account API Proxy

The My Account API proxy handles all requests to Auth0's My Account API at `/me/v1/*`.

### Configuration

Enable My Account API access by configuring the audience and scopes:

```ts
import { Auth0Client } from "@auth0/nextjs-auth0/server";

export const auth0 = new Auth0Client({
  useDPoP: true,
  authorizationParameters: {
    audience: "urn:your-api-identifier",
    scope: {
      [`https://${process.env.AUTH0_DOMAIN}/me/`]:
        "read:me:profile update:me:profile"
    }
  }
});
```

### Client-Side Usage

Make requests to the My Account API through the `/me/*` path:

```tsx
"use client";

import { useState } from "react";

export default function MyAccountProfile() {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchProfile = async () => {
    setLoading(true);
    try {
      const response = await fetch("/me/v1/profile", {
        method: "GET",
        headers: {
          scope: "read:me:profile"
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setProfile(data);
    } catch (error) {
      console.error("Failed to fetch profile:", error);
    } finally {
      setLoading(false);
    }
  };

  const updateProfile = async (updates) => {
    try {
      const response = await fetch("/me/v1/profile", {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          scope: "update:me:profile"
        },
        body: JSON.stringify(updates)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Failed to update profile:", error);
      throw error;
    }
  };

  return (
    <div>
      <button onClick={fetchProfile} disabled={loading}>
        {loading ? "Loading..." : "Load Profile"}
      </button>
      {profile && <pre>{JSON.stringify(profile, null, 2)}</pre>}
    </div>
  );
}
```

### `scope` Header

The `scope` header specifies the scope required for the request. The SDK uses this to retrieve an access token with the appropriate scope for the My Account API audience.

Format: `"scope": "scope1 scope2 scope3"`

Common scopes for My Account API:

- `read:me:profile` - Read the user's profile and field permissions
- `update:me:profile` - Update the user's writable profile attributes
- `read:me:connected_accounts` - List the user's connected accounts
- `create:me:connected_accounts` - Connect a new account
- `create:me:authentication_methods` - Enroll a new authentication method (for example, a passkey)

See the [My Account API documentation](https://auth0.com/docs/manage-users/my-account-api) for the full list of scopes.

## Managing the User Profile

The My Account API exposes the user's own profile at `/me/v1/profile`. Your app can read the profile and update root attributes on behalf of the logged-in user. These calls go through the [My Account API Proxy](#my-account-api-proxy), so no extra SDK setup is needed.

| Operation | Endpoint | Scope |
| --- | --- | --- |
| Read profile values and field permissions | `GET /me/v1/profile` | `read:me:profile` |
| Update writable root attributes | `PATCH /me/v1/profile` | `update:me:profile` |

### Auth0 Setup

- The profile endpoints must be enabled for your tenant. While they are disabled, the profile scopes cannot be granted and both endpoints return `403`. This is the same `403` you get for a missing scope, so the response alone doesn't tell you which one it is.
- In the Auth0 Dashboard, open the **Auth0 My Account API** and grant `read:me:profile` and `update:me:profile` to your application under **Application Access**. These scopes are not granted automatically. Without them, the endpoints return `403`.
- Request the scopes for the My Account API audience, as shown in [Configuration](#configuration).

### Reading the Profile

Every field has an entry in `profile_policy` that says whether the user can edit it. Use it to decide which fields to render as editable, instead of checking the connection type yourself. For example, by default `given_name` is `read_only` with reason `managed_by_identity_provider` for a social user, and `read_write` for a database user.

`profile_policy` is keyed by JSON Pointer (`/given_name`, not `given_name`). A field with no value for the user is missing from the root of the response but still has an entry in `profile_policy`, so render from `profile_policy` rather than from which fields are present. `reason` is only set when `access` is `read_only`.

The set of `reason` values can grow (for example, `managed_by_identity_provider` or `system_managed`), so treat `reason` as an open string and don't branch on a fixed list. Treat any `access` value other than `read_write` as read-only.

```tsx
"use client";

import { useEffect, useState } from "react";

type ProfileFieldPolicy = {
  access: "read_only" | "read_write";
  source: "user" | "idp" | "system";
  reason?: string;
};

type UserProfile = {
  user_id?: string;
  given_name?: string;
  family_name?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_verified?: boolean;
  username?: string;
  created_at?: string;
  updated_at?: string;
  profile_policy?: Record<string, ProfileFieldPolicy>;
  [key: string]: unknown;
};

export default function ProfileForm() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/me/v1/profile", {
      headers: { scope: "read:me:profile" }
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
      })
      .then(setProfile)
      .catch((err) => {
        console.error("Failed to fetch profile:", err);
        setError("Could not load your profile. Please try again.");
      });
  }, []);

  if (error) return <p role="alert">{error}</p>;
  if (!profile) return <p>Loading...</p>;

  return (
    <form>
      {["given_name", "family_name", "nickname"].map((field) => {
        const policy = profile.profile_policy?.[`/${field}`];
        return (
          <label key={field}>
            {field}
            <input
              name={field}
              defaultValue={(profile[field] as string) ?? ""}
              disabled={policy?.access !== "read_write"}
            />
          </label>
        );
      })}
    </form>
  );
}
```

To fetch only some fields, pass a comma-separated `fields` query parameter. Set `include_fields=false` to return every field except the ones listed.

```ts
const response = await fetch(
  "/me/v1/profile?fields=given_name,picture,profile_policy&include_fields=true",
  { headers: { scope: "read:me:profile" } }
);
```

> [!NOTE]
> When you pass `fields`, `profile_policy` is only returned if it is one of the selected fields, and it only contains entries for the selected fields. To get the complete `profile_policy`, make a request without `fields`.

### Updating Attributes

Send a `PATCH` with the fields to change. The response is the full profile, in the same shape as `GET`.

```ts
const response = await fetch("/me/v1/profile", {
  method: "PATCH",
  headers: {
    "content-type": "application/json",
    scope: "update:me:profile"
  },
  body: JSON.stringify({
    given_name: "Jane",
    nickname: "jdoe"
  })
});

const updatedProfile = await response.json();
```

The following root attributes can be updated: `given_name`, `family_name`, `name`, `nickname`, and `picture`. A field is only writable for a user when its `profile_policy` entry is `read_write`. For social and enterprise users, these fields are `read_only` by default because the identity provider updates them on each login.

`user_id`, `email_verified`, and `phone_verified` are read-only. Don't send them in an update.

Rules for root attributes:

- Fields you send replace the stored value. Fields you leave out are not changed.
- `null` is not allowed on root attributes. To leave a field unchanged, leave it out of the body.
- The update is all-or-nothing. If any field is rejected (for example, a write to a `read_only` field), nothing is saved.
- An empty body (`{}`) is valid. The server returns the current profile unchanged.

### Calling the API from the Server

From a Route Handler or Server Action, use a fetcher created with `auth0.createFetcher()`. It gets the user's access token for the My Account API audience and adds a DPoP proof when DPoP is enabled. Pass a `getAccessToken` that calls `auth0.getAccessToken()`, as shown below, so a refreshed token set (including a rotated refresh token) is saved to the session.

```ts
// app/api/profile/route.ts
import { auth0 } from "@/lib/auth0";

export async function PATCH(request: Request) {
  const fetcher = await auth0.createFetcher(undefined, {
    baseUrl: `https://${process.env.AUTH0_DOMAIN}`,
    getAccessToken: async (options) => {
      const { token, expiresAt, scope, token_type } =
        await auth0.getAccessToken(options);
      return { accessToken: token, expiresAt, scope, token_type };
    }
  });

  let response: Response;
  try {
    response = await fetcher.fetchWithAuth(
      "/me/v1/profile",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(await request.json())
      },
      {
        audience: `https://${process.env.AUTH0_DOMAIN}/me/`,
        scope: "update:me:profile"
      }
    );
  } catch (error) {
    // The API replied with a WWW-Authenticate challenge. Return its response
    // instead of failing the route. Rethrow everything else.
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "OAUTH_WWW_AUTHENTICATE_CHALLENGE" &&
      "response" in error &&
      error.response instanceof Response
    ) {
      response = error.response;
    } else {
      throw error;
    }
  }

  // Forward the headers callers need: `content-type` (errors are
  // `application/problem+json`) and `retry-after` (sent with `429`).
  const headers = new Headers();
  for (const name of ["content-type", "retry-after"]) {
    const value = response.headers.get(name);
    if (value) headers.set(name, value);
  }

  return new Response(response.body, { status: response.status, headers });
}
```

`fetchWithAuth` throws when the API replies with a `WWW-Authenticate` challenge, such as a `401` for an invalid token. The `catch` block returns that response so your caller gets the API's status and body.

> [!WARNING]
> Do not call the My Account API from a React Server Component. Getting the access token can rotate the refresh token, and Server Components cannot write cookies, so the rotated token is lost and the user is logged out on the next request. Call it from a Route Handler, Server Action, or middleware instead.

### Error Handling

Errors are returned as `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)).

| Status | Meaning |
| --- | --- |
| `400` | The request body is invalid, or it writes to a `read_only` field. Field-level details are returned in a `validation_errors` array (see below). |
| `401` | There is no active session, the token refresh failed, or the access token is missing or invalid. |
| `403` | The access token is missing the required scope, or the profile endpoints are not enabled for the tenant. Both cases can look the same, so check that the endpoints are enabled and that the scope is granted to your application. |
| `429` | Rate limit exceeded. Retry after the time in the `Retry-After` header. |

Only `detail` is always present in a `validation_errors` entry, and some `400` responses have no `validation_errors` at all. Don't assume the other properties exist:

- `detail` - A human-readable explanation
- `pointer` - A JSON Pointer ([RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)) to the field that failed, for example `/given_name`. It matches the key in `profile_policy`.
- `source` - A machine-readable reason, for example `managed_by_identity_provider`

```ts
if (response.status === 400) {
  const { detail, validation_errors = [] } = await response.json();
  if (validation_errors.length === 0) console.error(detail);
  for (const error of validation_errors) {
    console.error(error.pointer ? `${error.pointer}: ${error.detail}` : error.detail);
  }
}
```

### Limitations

- `email`, `phone_number`, and `username` cannot be changed with this endpoint.
- `user_metadata`, `app_metadata`, custom root-level attributes, and data from linked identities are not returned or writable.

## Integration with UI Components

When using Auth0 UI Components with the proxy handler, configure the client to target the proxy endpoints:

```tsx
import { MyAccountClient } from "@auth0/myaccount-js";

const myAccountClient = new MyAccountClient({
  domain: process.env.NEXT_PUBLIC_AUTH0_DOMAIN,
  baseUrl: "/me",
  fetcher: (url, init, authParams) => {
    return fetch(url, {
      ...init,
      headers: {
        ...init?.headers,
        scope: authParams?.scope?.join(" ") || ""
      }
    });
  }
});
```

This configuration:

- Sets `baseUrl` to `/me` to route requests through the proxy
- Passes the required scope via the `scope` header
- Ensures the SDK middleware handles authentication transparently
