import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md text-center space-y-6">
        <div>
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-600 text-white text-2xl shadow">
            🔄
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            Custom Token Exchange
          </h1>
          <p className="mt-2 text-sm text-gray-500">
            Exchange external tokens for Auth0 tokens using RFC 8693.
          </p>
        </div>

        <a
          href="/auth/login"
          className="block w-full rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white text-center transition hover:bg-indigo-700"
        >
          Log in to get started
        </a>

        <p className="text-xs text-gray-400">
          Log in first to get a session access token you can use as a subject
          token for the exchange demo.
        </p>
      </div>
    </main>
  );
}
