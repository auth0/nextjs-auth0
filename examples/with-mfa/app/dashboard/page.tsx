import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";
import { StepUp } from "./step-up";

export default async function Dashboard() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/");
  }

  return (
    <main className="mx-auto max-w-xl space-y-6 p-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">MFA step-up</h1>
          <p className="text-sm text-gray-500">
            Signed in as {session.user.email ?? session.user.sub}
          </p>
        </div>
        <a
          href="/auth/logout"
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-100"
        >
          Log out
        </a>
      </header>

      <StepUp audience={process.env.NEXT_PUBLIC_AUTH0_AUDIENCE ?? ""} />
    </main>
  );
}
