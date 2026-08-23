import { redirect } from "next/navigation";
import { getAppSession } from "@/lib/auth0";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  const session = await getAppSession();

  if (!session) {
    redirect("/login");
  }

  return (
    <main style={{ maxWidth: 600, margin: "60px auto", fontFamily: "sans-serif" }}>
      <h1>Dashboard</h1>
      <p style={{ color: "green", fontWeight: "bold" }}>
        Logged in via Enterprise Connect
      </p>

      <table style={{ borderCollapse: "collapse", width: "100%", marginTop: 24 }}>
        <tbody>
          {[
            ["Email", session.email],
            ["Name", session.name ?? "—"],
            ["org_id", session.orgId],
            ["sub", session.sub],
          ].map(([label, value]) => (
            <tr key={label} style={{ borderBottom: "1px solid #eee" }}>
              <td style={{ padding: "8px 12px", fontWeight: "bold", width: 120 }}>{label}</td>
              <td style={{ padding: "8px 12px", fontFamily: "monospace" }}>{value}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ marginTop: 32 }}>
        <a
          href="/api/logout"
          style={{ color: "#635DFF", textDecoration: "none", fontSize: 14 }}
        >
          Sign out (clears the app session and the enterprise IdP session)
        </a>
      </div>

      <details style={{ marginTop: 32, fontSize: 13, color: "#666" }}>
        <summary style={{ cursor: "pointer" }}>What to verify</summary>
        <ul style={{ marginTop: 8, lineHeight: 2 }}>
          <li>No <code>__session</code> cookie in browser DevTools, Application, Cookies (Auth0 writes none in EC mode); only <code>app_session</code> is set</li>
          <li>org_id above matches the organization Auth0 resolved for this email domain</li>
          <li>After logout, revisiting /dashboard redirects to /login</li>
        </ul>
      </details>
    </main>
  );
}
