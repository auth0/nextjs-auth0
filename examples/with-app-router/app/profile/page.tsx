import { auth0 } from "@/lib/auth0";
import { redirect } from "next/navigation";

export default async function ProfilePage() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/auth/login");
  }

  return (
    <main>
      <h1>👤 Your Profile</h1>

      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          backgroundColor: "#f0f9ff",
          borderRadius: "0.5rem"
        }}
      >
        <h2>User Information</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "1rem" }}>
          <dt><strong>Name:</strong></dt>
          <dd>{session.user.name || "N/A"}</dd>

          <dt><strong>Email:</strong></dt>
          <dd>{session.user.email || "N/A"}</dd>

          <dt><strong>ID:</strong></dt>
          <dd><code>{session.user.sub}</code></dd>

          <dt><strong>Email Verified:</strong></dt>
          <dd>{session.user.email_verified ? "✅ Yes" : "❌ No"}</dd>
        </dl>
      </div>

      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          backgroundColor: "#f5f5f5",
          borderRadius: "0.5rem"
        }}
      >
        <h2>Session Token Set</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "1rem" }}>
          <dt><strong>Access Token:</strong></dt>
          <dd><code>{session.tokenSet.accessToken.substring(0, 30)}...</code></dd>

          <dt><strong>ID Token:</strong></dt>
          <dd><code>{session.tokenSet.idToken?.substring(0, 30)}...</code></dd>

          <dt><strong>Expires At:</strong></dt>
          <dd>{new Date(session.tokenSet.expiresAt * 1000).toLocaleString()}</dd>
        </dl>
      </div>

      <div style={{ marginTop: "2rem", display: "flex", gap: "1rem" }}>
        <a
          href="/"
          style={{
            padding: "0.75rem 1.5rem",
            backgroundColor: "#0070f3",
            color: "white",
            textDecoration: "none",
            borderRadius: "0.5rem"
          }}
        >
          ← Back to Home
        </a>
        <a
          href="/auth/logout"
          style={{
            padding: "0.75rem 1.5rem",
            backgroundColor: "#666",
            color: "white",
            textDecoration: "none",
            borderRadius: "0.5rem"
          }}
        >
          Log Out
        </a>
      </div>
    </main>
  );
}
