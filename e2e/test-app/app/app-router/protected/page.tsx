import { auth0 } from "@/lib/auth0";

export default auth0.withPageAuthRequired(
  async function ProtectedPage() {
    const session = await auth0.getSession();
    return (
      <main>
        <h1 id="status">authenticated</h1>
        <p id="email">{session?.user.email}</p>
      </main>
    );
  },
  { returnTo: "/app-router/protected" }
);
