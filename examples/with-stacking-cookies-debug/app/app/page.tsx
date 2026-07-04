import { auth0 } from "@/lib/auth0";
import { redirect } from "next/navigation";

export default async function AppPage() {
  const session = await auth0.getSession();
  if (!session) redirect("/auth/login?returnTo=/app");

  return (
    <main style={{ maxWidth: 480, margin: "0 auto", padding: "48px 24px", fontFamily: "sans-serif" }}>
      <h1 style={{ fontSize: 20, marginBottom: 8, color: "#111827" }}>Signed in</h1>
      <p style={{ color: "#6b7280", fontSize: 13, marginBottom: 24 }}>
        Logged in as <strong>{session.user.email}</strong>.
      </p>
      <a href="/auth/logout" style={{
        display: "inline-block", background: "#dc2626", color: "white",
        borderRadius: 6, padding: "8px 16px", fontSize: 13, textDecoration: "none",
      }}>
        Sign out
      </a>
      <span style={{ marginLeft: 12 }}>
        <a href="/" style={{ fontSize: 13, color: "#6b7280" }}>← Home</a>
      </span>
    </main>
  );
}
