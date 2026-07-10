import { auth0 } from "@/lib/auth0";
import { redirect } from "next/navigation";

// Tests onCallback and beforeSessionSaved hooks — the auth0 instance in lib/auth0.ts
// must be configured with these hooks for the tests to observe their effects.
// This page just shows whether the session has the hook-injected fields.
export default async function HooksPage() {
  const session = await auth0.getSession();

  if (!session) redirect("/auth/login?returnTo=/app-router/hooks");

  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="custom-claim">{String(session.user.customClaim ?? "")}</p>
      <p id="session-field">{String(session.user.sessionField ?? "")}</p>
    </main>
  );
}
