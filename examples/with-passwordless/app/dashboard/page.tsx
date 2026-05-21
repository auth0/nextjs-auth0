import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

/**
 * Render the authenticated user's dashboard page.
 *
 * If no active session is found, performs a redirect to "/". When a session
 * exists, displays the user's identity and verification status, the derived
 * authentication method, session creation and token expiration times, token
 * type and scopes, access token availability, and a sign-out link.
 *
 * @returns A JSX element containing the dashboard UI that presents user and session/token information
 */
export default async function Dashboard() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/");
  }

  const { user, tokenSet, internal } = session;

  // Derive the auth method from the subject prefix:
  //   email|...   → Email OTP or Magic Link
  //   sms|...     → SMS OTP
  const method = user.sub?.startsWith("sms|")
    ? "SMS OTP"
    : user.sub?.startsWith("email|")
    ? "Email OTP / Magic Link"
    : "Passwordless";

  const createdAt = new Date(internal.createdAt * 1000).toLocaleTimeString();
  const expiresAt = new Date(tokenSet.expiresAt * 1000).toLocaleTimeString();
  const scopes = tokenSet.scope?.split(" ") ?? [];

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg space-y-4">

        {/* Success banner */}
        <div className="rounded-2xl border border-green-200 bg-green-50 p-6 text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-green-100">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold text-green-900">Signed in successfully</h1>
          <p className="mt-1 text-sm text-green-700">
            Authenticated via <span className="font-medium">{method}</span>
            {user.email && <> as <span className="font-medium">{user.email}</span></>}
            {user.phone_number && !user.email && <> as <span className="font-medium">{user.phone_number}</span></>}
          </p>
        </div>

        {/* User card */}
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-3">

              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gray-100 text-lg font-semibold text-gray-500">
                {(user.name ?? user.email ?? user.sub)[0].toUpperCase()}
              </div>
   
            <div>
              <p className="font-semibold text-gray-900">{user.name ?? user.email ?? (user.phone_number as string | undefined) ?? user.sub}</p>
              {user.email_verified !== undefined && (
                <p className="text-xs text-gray-500">
                  Email {user.email_verified ? "verified" : "not verified"}
                </p>
              )}
            </div>
          </div>

          <dl className="divide-y divide-gray-100 text-sm">
            {user.email && (
              <div className="flex justify-between py-2">
                <dt className="text-gray-500">Email</dt>
                <dd className="text-gray-900">{user.email}</dd>
              </div>
            )}
            {user.phone_number && (
              <div className="flex justify-between py-2">
                <dt className="text-gray-500">Phone</dt>
                <dd className="text-gray-900">{user.phone_number}</dd>
              </div>
            )}
            <div className="flex justify-between py-2">
              <dt className="text-gray-500">Auth method</dt>
              <dd className="text-gray-900">{method}</dd>
            </div>
          </dl>
        </div>

        {/* Token info — shows what the SDK set up after verify() */}
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-3 text-sm font-semibold text-gray-700">Session &amp; token</h2>
          <dl className="divide-y divide-gray-100 text-sm">
            <div className="flex justify-between py-2">
              <dt className="text-gray-500">Session created</dt>
              <dd className="text-gray-900">{createdAt}</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-gray-500">Access token expires</dt>
              <dd className="text-gray-900">{expiresAt}</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-gray-500">Token type</dt>
              <dd className="text-gray-900">{tokenSet.token_type ?? "Bearer"}</dd>
            </div>
            {scopes.length > 0 && (
              <div className="flex justify-between gap-4 py-2">
                <dt className="shrink-0 text-gray-500">Scopes</dt>
                <dd className="flex flex-wrap justify-end gap-1">
                  {scopes.map(s => (
                    <span key={s} className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-gray-700">{s}</span>
                  ))}
                </dd>
              </div>
            )}
            <div className="flex justify-between py-2">
              <dt className="text-gray-500">Access token</dt>
              <dd className="text-gray-900">{tokenSet.accessToken ? "Received" : "Not available"}</dd>
            </div>
          </dl>
        </div>

        <a
          href="/auth/logout"
          className="block w-full rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-50"
        >
          Sign out
        </a>
      </div>
    </main>
  );
}
