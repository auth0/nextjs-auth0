import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

import { SessionTransferForm } from "./session-transfer-form";

export default async function SttPage() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg space-y-6">
        <div>
          <a
            href="/dashboard"
            className="text-sm text-indigo-600 hover:underline"
          >
            ← Back to dashboard
          </a>
          <h1 className="mt-3 text-2xl font-bold">Session Transfer Token</h1>
          <p className="mt-1 text-sm text-gray-500">
            Request a one-shot token that lets you establish a session as a
            customer in another app — without their password.
          </p>
        </div>

        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800">
          <strong>Agent role only.</strong> Paste the customer&apos;s ID token
          or access token below. The returned redirect URL is valid for ~60
          seconds and must be opened in the agent&apos;s browser — it is
          single-use.
        </div>

        <SessionTransferForm />
      </div>
    </main>
  );
}
