import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";
import { PasswordlessDbForm } from "@/components/passwordless-db-form";

export default async function Home() {
  const session = await auth0.getSession();

  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Sign in</h1>
          <p className="mt-1 text-sm text-gray-500">
            Passwordless OTP on a database connection
          </p>
        </div>
        <PasswordlessDbForm />
      </div>
    </main>
  );
}
