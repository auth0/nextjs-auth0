---
name: organizations
description: >-
  Auth0 Organizations (multi-tenant B2B) with @auth0/nextjs-auth0 v4: pass
  organization at login via authorizationParameters / the /auth/login query
  param / startInteractiveLogin, read org_id back from the session, validate it
  on the backend, accept invitations, and configure orgs/connections via the
  Auth0 CLI or Terraform.
metadata:
  type: sub-skill
  library: nextjs-auth0
  library_version: 4.30.0
requires:
  - nextjs-auth0
---

# Auth0 Organizations (v4)

Multi-tenant B2B authentication. Organizations let each of your customers have their own isolated user pool, roles, and connections — all within one Auth0 tenant.

## When to use Organizations

Use Organizations when you need:
- Multiple business customers (tenants), each with their own users and SSO
- Per-org user roles and permissions
- Different login connections per customer (e.g., Okta SSO for CustomerA, Google Workspace for CustomerB)
- Organization-scoped invitations and member management

Do NOT use Organizations for consumer apps (B2C). Organizations is a B2B construct — use plain Auth0 connections within a single tenant for B2C, and reserve Organizations for B2B multi-tenant scenarios.

## Concepts

| Concept | Description |
|---|---|
| **Organization** | An isolated tenant within your Auth0 tenant. Has an `id` (org_xxx) and `name` (slug). |
| **Member** | A user belonging to an organization. A user can belong to multiple orgs. |
| **Org-level role** | A role granted to a user within a specific org (not globally). |
| **Connection** | A login method enabled for an org (database, enterprise SSO, social). |
| **Invitation** | A time-limited invite to join an org, sent by email. |

## Pass organization at login

The org-login shape is protocol-level: send the organization identifier on the `/authorize`
request, then read `org_id` back off the returned token. In `@auth0/nextjs-auth0` v4 there is
**no dedicated top-level `organization` option** — it goes inside `authorizationParameters`
(`AuthorizationParameters.organization?: string`). Pick the form that fits, most specific first:

**(a) Client-level default** (every login targets this org):

```ts
// lib/auth0.ts
export const auth0 = new Auth0Client({
  authorizationParameters: { organization: "org_abc123" },
});
```

**(b) Per-login via the `/auth/login` query param.** The login handler forwards every query
param except `returnTo`/`challengeMode` straight to `/authorize`, so `organization` (and
`invitation`, below) pass through automatically:

```tsx
<a href="/auth/login?organization=org_abc123&returnTo=/dashboard">Log in</a>
```

**(c) Per-login via a Route Handler calling `startInteractiveLogin` (type-safe):**

```ts
// app/auth/org-login/route.ts
import { auth0 } from "@/lib/auth0";

export const GET = async () =>
  auth0.startInteractiveLogin({
    authorizationParameters: { organization: "org_abc123" },
    returnTo: "/dashboard",
  });
```

Prefer a **per-login** form (b/c) over a client-wide default when the app serves more than one
org or accepts cross-org invitations — a pinned client default is validated against the returned
`org_id` at login completion and rejects members of other orgs. Never hand-roll the authorize URL.

## Reading the organization back

`org_id` is a **default** ID-token claim in v4, so it lands on the session automatically —
**no `beforeSessionSaved` hook needed** (unlike `amr`). Read it server-side:

```ts
const session = await auth0.getSession();
const orgId = session?.user.org_id; // string | undefined
```

`org_name` is **not** a typed/default claim. If your tenant emits it and you need it, opt it in
with a `beforeSessionSaved` hook (return the full `session` so the extra claim isn't filtered)
and read it as an untyped field on `session.user`.

- **To display which org the user is in (web/client):** read `org_id`/`org_name` from the session
  (backed by the ID token). Use the session user, not a hand-decoded token.
- **To authorize an API request (server side):** validate `org_id` from the **access token** the
  API receives (see below).

## Validate org on the backend

Validate the access token's `org_id` to prevent cross-tenant access, then segment data by it.
Check it against a **known list of organization IDs** or the org implied by request context (e.g.
tenant subdomain) — not a single hardcoded default. A fixed `!== defaultOrg` check is fine for a
single-org app but rejects valid members of other orgs in a multi-org app or one accepting
cross-org invitations.

```text
// orgId is the org_id claim from the *verified* access token.
if (!allowedOrgIds.has(orgId)) { /* reject: untrusted organization (e.g. 403) */ }
// then scope every data lookup by orgId
```

## Invitation flow

An invitation lets you add a user who has no Auth0 account yet. The invitee gets a link,
authenticates, and becomes a member.

Configure the tenant/app first — **two prerequisites, each a hard 400** before the first
`invitations create`:

```bash
# 1. Without this: "The specified client_id (...) does not allow organizations."
auth0 api patch "clients/<client-id>" \
  --data '{"organization_usage":"allow","organization_require_behavior":"no_prompt"}'

# 2. Without this: "A default login route is required to generate the invitation url."
#    Read the current value FIRST — it's tenant-wide; you may need to restore it.
auth0 api get "tenants/settings" | jq -r '.default_redirection_uri // ""'
auth0 api patch "tenants/settings" \
  --data '{"default_redirection_uri":"https://app.example.com/callback"}'
```

`default_redirection_uri` is validated as `absolute-https-uri-or-empty` (https only, `localhost`
rejected) and is **tenant-wide**. Capture the old value and restore it (`""` if it was empty) if
the invitation was the only reason you set it, or disclose the change in your summary.

```bash
auth0 orgs invitations create --org-id "<org-id>" \
  --invitee-email "user@company.com" --inviter-name "Admin" \
  --client-id "<client-id>" --roles "<role-id>" --send-email=false
```

`--send-email` **defaults to `true`** and needs the `=` form. Verify with
`auth0 orgs invitations list --org-id <org-id>`.

### Accepting an invitation (app side)

The invite link lands on your app carrying **both** an `invitation` and an `organization` param:

```
https://your-app.com/login?invitation={ticket_id}&organization={org_id}
```

Forward **both** to `/authorize`. In Next.js, route the user to `/auth/login` carrying both — the
login handler forwards them automatically (`organization` is typed; `invitation` rides through as
an untyped authorization param):

```
/auth/login?organization=org_abc123&invitation=<ticket_id>&returnTo=/
```

Forward the invite's **own** `organization` — do not substitute your app's configured default org.
Only fall back to a default when no `organization` is present. (The SDK forwards these params
mechanically; the invitation flow itself is standard Auth0, not separately documented in the SDK.)

## Tenant configuration (CLI / Terraform)

The Auth0 MCP server exposes **no** organizations tool, so use the CLI or Terraform.

| Operation | CLI | Terraform |
|---|---|---|
| Create an organization | `auth0 orgs create --name <slug> --display "<Name>"` | `auth0_organization` |
| List / show / update / delete | `auth0 orgs list` / `show` / `update` / `delete` | `auth0_organization` |
| Add a member | `auth0 api post "organizations/<org-id>/members" --data '{"members":["<user-id>"]}'` | `auth0_organization_member` |
| Enable a connection | `auth0 api post "organizations/<org-id>/enabled_connections" --data '{"connection_id":"<con-id>","assign_membership_on_login":true}'` | `auth0_organization_connections` |
| Assign an org-scoped role | `auth0 api post "organizations/<org-id>/members/<user-id>/roles" --data '{"roles":["<role-id>"]}'` | `auth0_organization_member_roles` |
| Create an invitation | `auth0 orgs invitations create` (see above) | not covered |

Verify subcommands with `auth0 commands orgs --detailed` and read flag names off `--help` rather
than inferring them; use `auth0 api` for anything without a dedicated subcommand. Reading
connections back returns a **bare array**, so use `jq '.[]'`, not `jq '.enabled_connections[]'`.

### Finding or creating a login connection

Reuse an existing database connection when the tenant has one; create one only if it does not:

```bash
# List database connections and pick one explicitly by name — the API defines no
# ordering, so `.[0]` silently grabs an arbitrary connection.
auth0 api get "connections?strategy=auth0" | jq -r '.[] | select(.name=="<connection-name>") | .id'

# Create one only if none matches. `name` must match ^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$, max 128.
auth0 api post connections --data '{"name":"<connection-name>","strategy":"auth0"}'

# Enable it for the organization — without this, org members have no way to log in.
auth0 api post "organizations/<org-id>/enabled_connections" \
  --data '{"connection_id":"<con-id>","assign_membership_on_login":true}'

# Enable it for each app that will use it — status false disables. Max 50 per call.
auth0 api patch "connections/<con-id>/clients" --data '[{"client_id":"<client-id>","status":true}]'
```

Connection reads are checkpoint-paginated (`take` defaults to 50): omit `from` on the first call,
then while the response carries a `next` value pass it as `from` until it is absent. Page through
all results before concluding a connection is absent, and fail unless exactly one matches.

A connection in the organization's `enabled_connections` is what appears at that org's login
prompt. Enabling the connection for a client (`connections/<con-id>/clients`) is a separate
setting governing the connection's availability to the app outside the org context — not what
enables organization login.

## Common mistakes

| Mistake | Fix |
|---|---|
| Not passing `organization` at login | Put it inside `authorizationParameters` (constructor default, `/auth/login?organization=…`, or `startInteractiveLogin`) |
| Not forwarding the `invitation` param when accepting an invite | Route to `/auth/login?organization=…&invitation=…`; the handler forwards both to `/authorize` |
| Using your default org for an invitation link | Forward the invite's own `organization` param — it may differ from your configured default |
| Pinning a client-wide default org while accepting cross-org invitations | A client-level `organization` is validated against the returned `org_id` at login and rejects invites to other orgs. Pass `organization` per login instead |
| Reading `org_id` from the wrong place | Web/client apps read it from the session/ID token (display); APIs validate it from the access token (authorization) |
| Adding a `beforeSessionSaved` hook to get `org_id` | Not needed — `org_id` is a default claim on `session.user`. Only `org_name` (untyped) needs the hook |
| Hand-decoding a token to read `org_id` | Use `session.user.org_id` — the claim is already exposed |
| Validating `org_id` against a single hardcoded org on the backend | Validate against the set of orgs the request may serve — a known list, or the org derived from request context |
| Mixing up org `id` (org_xxx) and `name` (slug) | `id` for API calls, `name` for display |
| Granting global roles instead of org-level roles | Use the org member roles endpoint, not the user roles endpoint |
| A space or underscore in a new connection's `name` | Alphanumerics and hyphens only, starting and ending alphanumeric. Anything else is a 400 |
| Overwriting `default_redirection_uri` without reading it first | It is tenant-wide. Capture the old value, and restore or disclose it |
| Prefixing `auth0 api` paths with `/api/v2/` | Paths are relative to the API root. `/api/v2/organizations/...` returns 404 |
| Inviting before setting `organization_usage` on the app and `default_redirection_uri` on the tenant | Both are hard 400s. Configure them first |
| Letting `auth0 orgs invitations create` send a live email | `--send-email` defaults to `true`. Pass `--send-email=false` |

## Multi-tenant architecture

For broader B2B SaaS architecture guidance (tenant isolation models, one Auth0 organization per
customer vs. shared connections), see Auth0's multi-tenant patterns documentation.
