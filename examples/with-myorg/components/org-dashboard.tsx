"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const PERM_INVITE = "create:my_org:member_invitations";
const PERM_READ_MEMBERS = "read:my_org:members";
const PERM_MANAGE_ROLES = "create:my_org:member_roles";

interface Member {
  user_id: string;
  name?: string;
  email?: string;
  picture?: string;
}

interface OrgDashboardProps {
  // Permissions are read server-side via getSession() and passed as props.
  // The claim is in the session cookie — no client-side SDK hook needed.
  permissions: string[];
}

export function OrgDashboard({ permissions }: OrgDashboardProps) {
  const permSet = useMemo(() => new Set(permissions), [permissions]);
  const can = (perm: string) => permSet.has(perm);

  const [org, setOrg] = useState<Record<string, unknown> | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [loadingData, setLoadingData] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchOrgData = useCallback(async () => {
    setLoadingData(true);
    setError(null);
    try {
      // All requests go through the SDK's built-in BFF proxy at /my-org/*.
      // The SDK attaches a server-side access token — the browser never sees it.
      const [orgRes, membersRes] = await Promise.all([
        fetch("/my-org/v1/config", { headers: { scope: "read:my_org:configuration" } }),
        permSet.has(PERM_READ_MEMBERS)
          ? fetch("/my-org/v1/members", { headers: { scope: "read:my_org:members" } })
          : Promise.resolve(null),
      ]);

      if (!orgRes.ok) throw new Error(`Failed to load org: ${orgRes.status}`);
      const orgData = await orgRes.json();
      setOrg(orgData);

      if (membersRes) {
        if (!membersRes.ok)
          throw new Error(`Failed to load members: ${membersRes.status}`);
        const membersData = await membersRes.json();
        setMembers(membersData.members ?? []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoadingData(false);
    }
  }, [permSet]);

  useEffect(() => {
    fetchOrgData();
  }, [fetchOrgData]);

  return (
    <div className="space-y-4">

      {/* Permissions badge row */}
      <div className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
        <h2 className="mb-2 text-sm font-semibold text-gray-700">Your permissions</h2>
        {permissions.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {permissions.map((p) => (
              <span
                key={p}
                className="rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-medium text-blue-700"
              >
                {p}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-500">No My Organization permissions assigned.</p>
        )}
        <p className="mt-2 text-xs text-gray-400">
          Sourced from the{" "}
          <code className="rounded bg-gray-100 px-1 py-0.5 font-mono text-xs">
            urn:auth0:my_org_current_user_permissions
          </code>{" "}
          ID token claim. Refreshed automatically when the session token renews.
        </p>
      </div>

      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">

        {/* Organization card */}
        <div className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-700">Organization</h2>
            <button
              type="button"
              onClick={fetchOrgData}
              disabled={loadingData}
              className="text-xs text-gray-400 hover:text-gray-700 disabled:opacity-40"
            >
              {loadingData ? "Loading…" : "Refresh"}
            </button>
          </div>

          {org ? (
            <pre className="overflow-auto rounded bg-gray-50 p-3 text-xs text-gray-700 max-h-40">
              {JSON.stringify(org, null, 2)}
            </pre>
          ) : (
            !loadingData && (
              <p className="text-sm text-gray-400">No organization data.</p>
            )
          )}

          {/* Invite button — gated on my_org:invite_members */}
          <div className="mt-4">
            <button
              type="button"
              disabled={!can(PERM_INVITE)}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition"
              title={can(PERM_INVITE) ? "Invite a new member" : `Requires ${PERM_INVITE}`}
            >
              + Invite Member
            </button>
            {!can(PERM_INVITE) && (
              <p className="mt-1 text-xs text-gray-400">
                Requires <code className="rounded bg-gray-100 px-1">{PERM_INVITE}</code>
              </p>
            )}
          </div>
        </div>

        {/* Members card */}
        <div className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
          <h2 className="mb-4 text-sm font-semibold text-gray-700">Members</h2>

          {!can(PERM_READ_MEMBERS) ? (
            <p className="text-sm text-gray-400">
              Requires{" "}
              <code className="rounded bg-gray-100 px-1 text-xs">{PERM_READ_MEMBERS}</code>{" "}
              to view members.
            </p>
          ) : loadingData ? (
            <p className="text-sm text-gray-400">Loading…</p>
          ) : members.length === 0 ? (
            <p className="text-sm text-gray-400">No members found.</p>
          ) : (
            <ul className="divide-y divide-gray-100">
              {members.map((m) => (
                <li key={m.user_id} className="flex items-center gap-3 py-2">
                  {m.picture ? (
                    <img
                      src={m.picture}
                      alt={m.name ?? m.email}
                      className="h-8 w-8 rounded-full"
                    />
                  ) : (
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 text-xs font-semibold text-gray-500">
                      {(m.name ?? m.email ?? "?").charAt(0).toUpperCase()}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <p className="truncate text-sm font-medium text-gray-900">
                      {m.name ?? m.email}
                    </p>
                    {m.name && m.email && (
                      <p className="truncate text-xs text-gray-500">{m.email}</p>
                    )}
                  </div>
                  {/* Manage roles — gated on my_org:manage_member_roles */}
                  <button
                    type="button"
                    disabled={!can(PERM_MANAGE_ROLES)}
                    className="shrink-0 text-xs text-blue-600 hover:text-blue-800 disabled:opacity-30 disabled:cursor-not-allowed"
                    title={
                      can(PERM_MANAGE_ROLES)
                        ? "Manage roles"
                        : `Requires ${PERM_MANAGE_ROLES}`
                    }
                  >
                    Roles
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

      </div>
    </div>
  );
}
