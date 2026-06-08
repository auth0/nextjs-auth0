import { redirect } from "next/navigation";

import { PasskeyForm } from "@/components/passkey-form";
import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-600 text-white text-2xl shadow">
            🔑
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Sign in</h1>
          <p className="mt-2 text-sm text-gray-500">
            Use a passkey — your fingerprint, face, or device PIN — no password
            needed.
          </p>
        </div>

        <PasskeyForm />

        <p className="mt-6 text-center text-xs text-gray-400">
          Want full control?{" "}
          <a href="/signup-advanced" className="underline hover:text-gray-600">
            Step-by-step example with Server Actions
          </a>
        </p>
      </div>
    </main>
  );
}
