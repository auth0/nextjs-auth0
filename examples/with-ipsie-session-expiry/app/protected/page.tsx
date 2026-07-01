import { auth0 } from "@/lib/auth0";

export default auth0.withPageAuthRequired(async function ProtectedPage() {
  const session = await auth0.getSession();

  return (
    <main>
      <h1>Protected Page</h1>
      <p style={{ color: "#6b7280" }}>
        This page is wrapped with <code>withPageAuthRequired()</code>. Once the
        IPSIE session ceiling passes, accessing this URL will redirect to{" "}
        <code>/auth/login</code> instead of rendering this content.
      </p>
      <div className="card">
        <div className="label">Logged in as</div>
        <div className="value">{session?.user?.email ?? "—"}</div>
      </div>
      <p style={{ marginTop: "1rem", fontSize: "0.875rem" }}>
        <a href="/">← Back to main page</a>
      </p>
    </main>
  );
});
