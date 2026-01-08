import { auth0 } from "@/lib/auth0";

export default async function Home() {
  const session = await auth0.getSession();

  return (
    <main>
      <h1>🔐 Auth0 Next.js - API Routes Example</h1>

      {!session ? (
        <div>
          <p>You are not logged in.</p>
          <p>
            This example uses <strong>API routes</strong> instead of middleware
            to mount authentication routes.
          </p>
          <div style={{ marginTop: "2rem" }}>
            <a
              href="/api/auth/login"
              style={{
                padding: "0.75rem 1.5rem",
                backgroundColor: "#0070f3",
                color: "white",
                textDecoration: "none",
                borderRadius: "0.5rem",
                display: "inline-block"
              }}
            >
              Log In
            </a>
          </div>
        </div>
      ) : (
        <div>
          <p>
            Welcome, <strong>{session.user.name || session.user.email}</strong>!
          </p>
          <div style={{ marginTop: "1rem", display: "flex", gap: "1rem" }}>
            <a
              href="/profile"
              style={{
                padding: "0.75rem 1.5rem",
                backgroundColor: "#0070f3",
                color: "white",
                textDecoration: "none",
                borderRadius: "0.5rem"
              }}
            >
              View Profile
            </a>
            <a
              href="/api/auth/logout"
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
        </div>
      )}

      <div
        style={{
          marginTop: "3rem",
          padding: "1.5rem",
          backgroundColor: "#f5f5f5",
          borderRadius: "0.5rem"
        }}
      >
        <h2>How It Works</h2>
        <p>This example demonstrates:</p>
        <ul>
          <li>
            <strong>API Route Mounting:</strong> Auth routes are handled by{" "}
            <code>app/api/[...auth0]/route.ts</code>
          </li>
          <li>
            <strong>No Middleware:</strong> Authentication doesn&apos;t use middleware
          </li>
          <li>
            <strong>Simple Setup:</strong> Just 3 lines to export GET and POST
            handlers
          </li>
          <li>
            <strong>Route Mapping:</strong> <code>/api/auth/login</code> →{" "}
            <code>["auth", "login"]</code> → reconstructed as <code>/auth/login</code>
          </li>
        </ul>
        <p>
          Check the <code>README.md</code> for more details!
        </p>
      </div>
    </main>
  );
}
