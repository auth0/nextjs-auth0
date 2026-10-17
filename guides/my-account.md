# My Account API

Examples for calling the [Auth0 My Account API](https://auth0.com/docs/manage-users/my-account-api) from your Next.js application with the Auth0 Next.js SDK. This covers the built-in `/me` proxy, managing the user's profile and `user_metadata`, and integration with Auth0 UI Components.

For how the proxy works in general (supported HTTP methods, CORS, token management, and security considerations), see [Proxy Handler for My Account and My Organization APIs](../EXAMPLES.md#proxy-handler-for-my-account-and-my-organization-apis).

[← Back to EXAMPLES.md](../EXAMPLES.md)

- [My Account API Proxy](#my-account-api-proxy)
  - [Configuration](#configuration)
  - [Client-Side Usage](#client-side-usage)
  - [`scope` Header](#scope-header)
- [Managing User Profile and Metadata](#managing-user-profile-and-metadata)
  - [Auth0 Setup](#auth0-setup)
  - [Reading the Profile](#reading-the-profile)
  - [Updating Attributes and Metadata](#updating-attributes-and-metadata)
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

- `read:me:profile` - Read the user's profile, `user_metadata`, and field permissions
- `update:me:profile` - Update the user's writable profile attributes and `user_metadata`
- `read:me:connected_accounts` - List the user's connected accounts
- `create:me:connected_accounts` - Connect a new account
- `create:me:authentication_methods` - Enroll a new authentication method (for example, a passkey)

See the [My Account API documentation](https://auth0.com/docs/manage-users/my-account-api) for the full list of scopes.

## Managing User Profile and Metadata

The My Account API exposes the user's own profile at `/me/v1/profile`. Your app can read the profile, update root attributes, and manage `user_metadata` on behalf of the logged-in user. These calls go through the [My Account API Proxy](#my-account-api-proxy), so no extra SDK setup is needed.

| Operation | Endpoint | Scope |
| --- | --- | --- |
| Read profile values and field permissions | `GET /me/v1/profile` | `read:me:profile` |
| Update writable root attributes and `user_metadata` | `PATCH /me/v1/profile` | `update:me:profile` |

### Auth0 Setup

- The profile endpoints must be enabled for your tenant. While they are disabled, both endpoints return `404`.
- In the Auth0 Dashboard, open the **Auth0 My Account API** and grant `read:me:profile` and `update:me:profile` to your application under **Application Access**. These scopes are not granted automatically. Without them, the endpoints return `403`.
- Request the scopes for the My Account API audience, as shown in [Configuration](#configuration).

### Reading the Profile

Every field has an entry in `profile_policy` that says whether the user can edit it. Use it to decide which fields to render as editable, instead of checking the connection type yourself. For example, by default `given_name` is `read_only` with reason `managed_by_identity_provider` for a social user, and `read_write` for a database user.

`profile_policy` is keyed by JSON Pointer (`/given_name`, not `given_name`). A field with no value for the user is missing from the root of the response but still has an entry in `profile_policy`, so render from `profile_policy` rather than from which fields are present. `reason` is only set when `access` is `read_only`.

```tsx
"use client";

import { useEffect, useState } from "react";

type ProfileFieldPolicy = {
  label: string;
  access: "read_only" | "read_write";
  source: "user" | "idp" | "system";
  reason?:
    | "policy_read_only"
    | "managed_by_identity_provider"
    | "managed_via_me_identifiers"
    | "system_field";
};

type UserProfile = {
  given_name?: string;
  family_name?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  email?: string;
  user_metadata?: Record<string, unknown>;
  profile_policy?: Record<string, ProfileFieldPolicy>;
  [key: string]: unknown;
};

export default function ProfileForm() {
  const [profile, setProfile] = useState<UserProfile | null>(null);

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
      .catch((error) => console.error("Failed to fetch profile:", error));
  }, []);

  if (!profile) return <p>Loading...</p>;

  return (
    <form>
      {["given_name", "family_name", "nickname"].map((field) => {
        const policy = profile.profile_policy?.[`/${field}`];
        return (
          <label key={field}>
            {policy?.label ?? field}
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

To read only metadata, request `fields=user_metadata`. There is no separate metadata endpoint.

### Updating Attributes and Metadata

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
    nickname: "jdoe",
    user_metadata: {
      theme: "dark", // adds or updates this key
      legacy_flag: null // deletes this key
    }
  })
});

const updatedProfile = await response.json();
```

The following root attributes can be updated: `given_name`, `family_name`, `name`, `nickname`, and `picture`. A field is only writable for a user when its `profile_policy` entry is `read_write`. For social and enterprise users, these fields are `read_only` by default because the identity provider updates them on each login.

Rules for root attributes:

- Fields you send replace the stored value. Fields you leave out are not changed.
- `null` is not allowed on root attributes. To leave a field unchanged, leave it out of the body.
- The update is all-or-nothing. If any field is rejected (for example, a write to a `read_only` field), nothing is saved.
- An empty body (`{}`) is valid. The server returns the current profile unchanged.

Rules for `user_metadata`:

- Only the top-level keys you send are changed. Other keys are not changed.
- A key you send replaces its stored value. Nested objects are replaced as a whole, not merged.
- Setting a key to `null` deletes it. Deleting a key that does not exist is not an error.
- Setting a key to `{}` stores an empty object. It does not delete the key.
- Sending `user_metadata: {}` leaves the metadata unchanged. The rest of the update still applies.
- Do not set `user_metadata` itself to `null`. The server rejects the request, and there is no way to clear all metadata in one call.
- Do not remove `null` values before sending the body. `JSON.stringify` keeps them, but a helper that strips `null` values would drop the delete.

`user_metadata` limits:

| Limit | Value |
| --- | --- |
| Top-level keys per request | 10 |
| Top-level keys in total, after the update | 100 |
| Total size, after the update | 10 KB |
| Key names | Cannot be empty, must start with a letter or number, and cannot contain `.` or `$` at any nesting depth. Top-level keys can be at most 100 characters. |
| String values | Cannot contain control characters (U+0000 to U+001F) |

### Calling the API from the Server

From a Route Handler, Server Action, or API route, use a fetcher created with `auth0.createFetcher()`. It gets the user's access token for the My Account API audience and adds a DPoP proof when DPoP is enabled.

```ts
// app/api/profile/route.ts
import { auth0 } from "@/lib/auth0";

export async function PATCH(request: Request) {
  const fetcher = await auth0.createFetcher(undefined, {
    baseUrl: `https://${process.env.AUTH0_DOMAIN}`
  });

  const response = await fetcher.fetchWithAuth(
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

  return new Response(response.body, {
    status: response.status,
    headers: { "content-type": "application/json" }
  });
}
```

> [!WARNING]
> Do not call the My Account API from a React Server Component. Getting the access token can rotate the refresh token, and Server Components cannot write cookies, so the rotated token is lost and the user is logged out on the next request. Call it from a Route Handler, Server Action, API route, or middleware instead.

### Error Handling

Errors are returned as `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)).

| Status | Meaning |
| --- | --- |
| `400` | The request body is invalid, or it writes to a `read_only` field. Field-level details are returned in a `validation_errors` array (see below). |
| `401` | There is no active session, the token refresh failed, or the access token is missing or invalid. |
| `403` | The access token is missing the required scope. Check that the scope is granted to your application. |
| `404` | The profile endpoints are not enabled on the tenant. Treat this as "feature not available", not as a missing resource. |
| `429` | Rate limit exceeded. Retry after the time in the `Retry-After` header. |

When present, each entry in `validation_errors` has three fields:

- `pointer` - A JSON Pointer ([RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)) to the field that failed, for example `/given_name`. It matches the key in `profile_policy`.
- `detail` - A human-readable explanation
- `source` - A machine-readable reason, using the same values as `profile_policy[field].reason`

```ts
if (response.status === 400) {
  const { validation_errors = [] } = await response.json();
  for (const error of validation_errors) {
    console.error(`${error.pointer}: ${error.detail} (${error.source})`);
  }
}
```

### Limitations

- `email`, `phone_number`, and `username` cannot be changed with this endpoint.
- `app_metadata`, custom root-level attributes, and data from linked identities are not returned or writable.
- Field selection applies to `user_metadata` as a whole. You cannot select individual metadata keys.

## Integration with UI Components

When using Auth0 UI Components with the proxy handler, configure the client to target the proxy endpoints:

```tsx
import { MyAccountClient } from "@auth0/my-account-js";

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
