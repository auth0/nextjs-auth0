import Link from "next/link";
import { auth0 } from "@/lib/auth0";

export default async function BugsLayout({ children }: { children: React.ReactNode }) {
  const session = await auth0.getSession();

  return (
    <div style={{ maxWidth: 600, margin: "0 auto", padding: "40px 24px", fontFamily: "sans-serif" }}>
      {/* Top bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <Link href="/" style={{ fontSize: 13, color: "#6b7280" }}>← Home</Link>
        <div style={{ fontSize: 13 }}>
          {session
            ? <><span style={{ color: "#6b7280", marginRight: 12 }}>{session.user.email}</span><a href="/auth/logout" style={{ color: "#dc2626" }}>Sign out</a></>
            : <a href="/auth/login" style={{ color: "#16a34a" }}>Sign in</a>}
        </div>
      </div>

      {children}
    </div>
  );
}
