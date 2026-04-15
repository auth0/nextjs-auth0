import { redirect } from "next/navigation";

import { PasswordlessForm } from "@/components/passwordless-form";
import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  // Already authenticated — go straight to the dashboard
  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold tracking-tight">Sign in</h1>
          <p className="mt-2 text-sm text-gray-500">
            Choose your preferred method: one-time code via email or SMS, or a
            magic link sent to your inbox — no password needed.
          </p>
        </div>

        <PasswordlessForm />
      </div>
    </main>
  );
}
