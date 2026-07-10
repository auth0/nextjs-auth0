import { auth0 } from "@/lib/auth0";

export default async function ServerPage() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <h1 id="status">unauthenticated</h1>
        <a href="/auth/login?returnTo=/app-router/server">Log in</a>
      </main>
    );
  }

  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="email">{session.user.email}</p>
      <p id="sub">{session.user.sub}</p>
      <p id="updated-at">{String(session.user.updatedAt ?? "")}</p>
    </main>
  );
}
