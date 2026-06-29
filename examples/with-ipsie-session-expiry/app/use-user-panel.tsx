"use client";

import { useUser } from "@auth0/nextjs-auth0/client";

export function UseUserPanel() {
  const { user, isLoading, error } = useUser();

  return (
    <div>
      <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
        Calls <code>/auth/profile</code> via the <code>useUser()</code> SWR
        hook. After the ceiling passes, <code>handleProfile</code> returns 401
        and the hook reflects a logged-out state — <code>user</code> becomes{" "}
        <code>undefined</code>.
      </p>

      {isLoading && (
        <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>Loading…</p>
      )}

      {!isLoading && error && (
        <div className="error">
          Hook error: {error.message}
        </div>
      )}

      {!isLoading && !error && (
        <pre className="token" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
          {user ? JSON.stringify({ user }, null, 2) : "user: undefined (logged-out state)"}
        </pre>
      )}
    </div>
  );
}
