import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-6 text-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">MFA step-up</h1>
          <p className="mt-2 text-sm text-gray-500">
            Log in without MFA, then ask for a token for the protected API.
          </p>
        </div>
        <a
          href="/auth/login"
          className="block w-full rounded-lg bg-rose-600 px-4 py-2.5 text-center text-sm font-semibold text-white transition hover:bg-rose-700"
        >
          Log in
        </a>
      </div>
    </main>
  );
}
