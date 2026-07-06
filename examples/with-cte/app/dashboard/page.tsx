import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

export default async function Dashboard() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/");
  }

  const { user, tokenSet } = session;

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg space-y-6">
        {/* Session card */}
        <div className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
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
              {user.name && <p className="text-gray-500">{user.name}</p>}
            </div>
          </div>

          <dl className="mb-6 divide-y divide-gray-100 rounded-lg border border-gray-100 bg-gray-50 p-4 text-sm">
            {user.email && (
              <div className="flex justify-between py-2">
                <dt className="font-medium text-gray-600">Email</dt>
                <dd className="text-gray-900">{user.email}</dd>
              </div>
            )}
            <div className="flex justify-between py-2">
              <dt className="font-medium text-gray-600">Subject</dt>
              <dd className="max-w-xs truncate text-gray-900">{user.sub}</dd>
            </div>
            {user.act && (
              <div className="flex justify-between py-2">
                <dt className="font-medium text-gray-600">Actor (act claim)</dt>
                <dd className="max-w-xs truncate font-mono text-xs text-indigo-700">
                  {JSON.stringify(user.act)}
                </dd>
              </div>
            )}
          </dl>

          <div className="flex gap-3">
            <a
              href="/cte"
              className="flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-center text-sm font-medium text-white transition hover:bg-indigo-700"
            >
              Try Token Exchange →
            </a>
            <a
              href="/stt"
              className="flex-1 rounded-lg bg-violet-600 px-4 py-2 text-center text-sm font-medium text-white transition hover:bg-violet-700"
            >
              Session Transfer →
            </a>
            <a
              href="/auth/logout"
              className="flex-1 rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-100"
            >
              Log out
            </a>
          </div>
        </div>

        {/* Access token card — useful as a subject token for CTE */}
        <div className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
          <h2 className="mb-1 text-lg font-semibold">Your access token</h2>
          <p className="mb-4 text-xs text-gray-400">
            You can use this token as the{" "}
            <code className="rounded bg-gray-100 px-1">subjectToken</code> on
            the exchange page to try a self-exchange scenario.
          </p>
          <pre className="overflow-x-auto rounded-lg border border-gray-100 bg-gray-50 p-3 text-xs text-gray-700 whitespace-pre-wrap break-all">
            {tokenSet.accessToken}
          </pre>
        </div>
      </div>
    </main>
  );
}
