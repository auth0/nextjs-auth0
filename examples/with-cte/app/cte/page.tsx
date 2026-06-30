import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";
import { TokenExchangeForm } from "./token-exchange-form";

export default async function CTEPage() {
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
          <h1 className="mt-3 text-2xl font-bold">Custom Token Exchange</h1>
          <p className="mt-1 text-sm text-gray-500">
            Exchange an external token for Auth0 tokens via RFC 8693. Paste any
            token below and provide its type URI.
          </p>
        </div>

        <TokenExchangeForm />
      </div>
    </main>
  );
}
