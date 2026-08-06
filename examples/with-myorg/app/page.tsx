import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";
import { OrgDashboard } from "@/components/org-dashboard";

export default async function Page() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/auth/login");
  }

  // Read the permissions claim server-side to avoid a flash of disabled controls
  // on first render. The claim is included automatically — no extra scope needed.
  const permissions: string[] =
    session.user["urn:auth0:my_org_current_user_permissions"] ?? [];

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-2xl">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">My Organization</h1>
            <p className="mt-1 text-sm text-gray-500">
              BFF proxy + permission-based UI gating via{" "}
              <code className="rounded bg-gray-100 px-1 py-0.5 text-xs">
                urn:auth0:my_org_current_user_permissions
              </code>
            </p>
          </div>
          <a
            href="/auth/logout"
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50 transition"
          >
            Sign out
          </a>
        </div>

        <OrgDashboard permissions={permissions} />
      </div>
    </main>
  );
}
