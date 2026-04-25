import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

export default async function Dashboard() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/");
  }

  const { user } = session;

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-4">
          {user.picture && (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={user.picture}
              alt={user.name ?? "User avatar"}
              className="h-14 w-14 rounded-full"
            />
          )}
          <div>
            <h1 className="text-2xl font-bold">Welcome back!</h1>
            {user.name && (
              <p className="text-gray-500">{user.name}</p>
            )}
          </div>
        </div>

        <dl className="mb-6 divide-y divide-gray-100 rounded-lg border border-gray-100 bg-gray-50 p-4 text-sm">
          {user.email && (
            <div className="flex justify-between py-2">
              <dt className="font-medium text-gray-600">Email</dt>
              <dd className="text-gray-900">{user.email}</dd>
            </div>
          )}
          {user.phone_number && (
            <div className="flex justify-between py-2">
              <dt className="font-medium text-gray-600">Phone</dt>
              <dd className="text-gray-900">{user.phone_number}</dd>
            </div>
          )}
          <div className="flex justify-between py-2">
            <dt className="font-medium text-gray-600">Subject</dt>
            <dd className="truncate max-w-xs text-gray-900">{user.sub}</dd>
          </div>
          {user.email_verified !== undefined && (
            <div className="flex justify-between py-2">
              <dt className="font-medium text-gray-600">Email verified</dt>
              <dd className="text-gray-900">
                {user.email_verified ? "Yes" : "No"}
              </dd>
            </div>
          )}
        </dl>

        <a
          href="/auth/logout"
          className="block w-full rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-100"
        >
          Log out
        </a>
      </div>
    </main>
  );
}
