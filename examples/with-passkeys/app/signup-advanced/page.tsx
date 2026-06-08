import { redirect } from "next/navigation";

import { PasskeyAdvancedForm } from "@/components/passkey-advanced-form";
import { auth0 } from "@/lib/auth0";

export default async function SignupAdvanced() {
  const session = await auth0.getSession();

  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-600 text-white text-2xl shadow">
            🔐
          </div>
          <h1 className="text-3xl font-bold tracking-tight">Step-by-step passkey</h1>
          <p className="mt-2 text-sm text-gray-500">
            Server Actions handle challenge and verify — giving you full control
            to add custom logic at each step.
          </p>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
          <PasskeyAdvancedForm />
        </div>

        <p className="mt-6 text-center text-xs text-gray-400">
          <a href="/" className="underline hover:text-gray-600">
            Back to simple example
          </a>
        </p>
      </div>
    </main>
  );
}
