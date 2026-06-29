import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";
import { AccessTokenPanel } from "./access-token-panel";
import { CeilingCountdown } from "./ceiling-countdown";
import { SessionCheckPanel } from "./session-check-panel";
import { UseUserPanel } from "./use-user-panel";
import { UpdateSessionPanel } from "./update-session-panel";
import { WithApiAuthPanel } from "./with-api-auth-panel";

export default async function Page() {
  const session = await auth0.getSession();

  if (!session) {
    redirect("/auth/login");
  }

  const { user, internal } = session;
  const ceiling = typeof internal.sessionExpiresAt === "number" ? internal.sessionExpiresAt : null;
  const createdAt = internal.createdAt;

  const hasNoCeiling = ceiling === null;

  return (
    <main>
      <h1>IPSIE Session Expiry Demo</h1>
      <p style={{ color: "#6b7280", marginBottom: "1.5rem" }}>
        This example demonstrates how the SDK enforces the{" "}
        <code>session_expiry</code> ceiling emitted by Auth0 for enterprise
        connections. Each card below exercises a different SDK code path.
      </p>

      {hasNoCeiling && (
        <div style={{
          background: "#fef9c3",
          border: "1px solid #fde047",
          borderRadius: "0.5rem",
          padding: "0.875rem 1rem",
          marginBottom: "1rem",
          fontSize: "0.875rem",
          color: "#713f12"
        }}>
          <strong>No ceiling found.</strong> The <code>session_expiry</code> claim
          is missing from the ID token. Add a Post-Login Action (see README) and
          log in fresh — ceiling enforcement will not fire without it.
        </div>
      )}

      {/* ── 1. User ─────────────────────────────────────────── */}
      <div className="card">
        <h2>User</h2>
        <div className="label">Name</div>
        <div className="value">{user.name ?? "—"}</div>
        <div className="label" style={{ marginTop: "0.75rem" }}>Email</div>
        <div className="value">{user.email ?? "—"}</div>
      </div>

      {/* ── 2. IPSIE ceiling countdown ───────────────────────── */}
      <div className="card">
        <h2>IPSIE Session Ceiling</h2>
        {ceiling === null ? (
          <p style={{ color: "#6b7280", fontSize: "0.875rem" }}>
            No ceiling — add the Post-Login Action and log in fresh.
          </p>
        ) : (
          <CeilingCountdown ceiling={ceiling} />
        )}
      </div>

      {/* ── 3. Middleware rolling session ───────────────────── */}
      <div className="card">
        <h2>Middleware — Rolling Session</h2>
        <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
          Every request passes through <code>auth0.middleware()</code> which
          re-sets the session cookie (rolling). The <code>createdAt</code> below
          is stamped at login and should <em>not</em> change on refresh — only
          the cookie expiry rolls. Once the ceiling passes, the middleware sees a
          null session and stops rolling entirely.
        </p>
        <div className="label" style={{ marginTop: "0.75rem" }}>
          session.internal.createdAt
        </div>
        <div className="value">
          {createdAt} &nbsp;
          <span style={{ color: "#6b7280", fontSize: "0.8rem" }}>
            ({new Date(createdAt * 1000).toLocaleString()})
          </span>
        </div>
        <p style={{ fontSize: "0.8rem", color: "#6b7280", marginTop: "0.5rem" }}>
          Reload this page repeatedly — the value stays constant. After the
          ceiling passes, reloading redirects to login instead.
        </p>
      </div>

      {/* ── 4. getSession — server read ─────────────────────── */}
      <div className="card">
        <h2>getSession() — Server Read</h2>
        <SessionCheckPanel />
      </div>

      {/* ── 5. useUser() — browser hook ─────────────────────── */}
      <div className="card">
        <h2>useUser() — Browser Hook</h2>
        <UseUserPanel />
      </div>

      {/* ── 6. getAccessToken — browser ─────────────────────── */}
      <div className="card">
        <h2>getAccessToken() — Browser</h2>
        <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
          Calls <code>/auth/access-token</code>. Once the ceiling is reached this
          returns a <code>session_expired</code> error without contacting Auth0.
        </p>
        <AccessTokenPanel />
      </div>

      {/* ── 7. withApiAuthRequired ───────────────────────────── */}
      <div className="card">
        <h2>withApiAuthRequired() — Protected API Route</h2>
        <WithApiAuthPanel />
      </div>

      {/* ── 8. updateSession ─────────────────────────────────── */}
      <div className="card">
        <h2>updateSession() — Session Write</h2>
        <UpdateSessionPanel />
      </div>

      {/* ── 9. withPageAuthRequired ──────────────────────────── */}
      <div className="card">
        <h2>withPageAuthRequired() — Protected Page</h2>
        <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
          Visit{" "}
          <a href="/protected" target="_blank">
            /protected
          </a>{" "}
          — it renders normally before the ceiling. After the ceiling, opening
          that URL redirects to <code>/auth/login</code> instead.
        </p>
      </div>

      {/* ── 10. ID token claims ──────────────────────────────── */}
      <div className="card">
        <h2>ID Token Claims</h2>
        <p style={{ fontSize: "0.875rem", color: "#6b7280", marginBottom: "0.75rem" }}>
          Verified claims from the ID token, sourced from <code>session.user</code>.{" "}
          <code>session_expiry</code> should appear here after adding the Post-Login
          Action and logging in fresh.
        </p>
        <pre className="token" style={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(user, null, 2)}
        </pre>
      </div>

      <div style={{ marginTop: "1rem", fontSize: "0.875rem" }}>
        <a href="/auth/logout">Log out</a>
      </div>
    </main>
  );
}
