/**
 * Login page using a plain HTML form POST to /api/login (server-side pattern).
 *
 * The browser POSTs directly to /api/login and follows the route handler's
 * redirect natively — no fetch, no CORS. The transaction cookie set by
 * startInteractiveLogin rides on that redirect response to /auth/callback.
 *
 * For the client-only variant (browser-side startEnterpriseLogin),
 * see /login/client.
 */
export default function LoginPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  return (
    <LoginForm searchParams={searchParams} />
  );
}

async function LoginForm({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;

  return (
    <main style={{ maxWidth: 400, margin: "100px auto", fontFamily: "sans-serif" }}>
      <h1>Acme — Sign in</h1>
      <p style={{ color: "#666", fontSize: 14 }}>
        Enter your work email to sign in with enterprise SSO.
      </p>

      <form
        method="POST"
        action="/api/login"
        style={{ display: "flex", flexDirection: "column", gap: 12 }}
      >
        <input
          name="email"
          type="email"
          placeholder="you@yourcompany.com"
          required
          style={{ padding: "10px 12px", fontSize: 16, border: "1px solid #ccc", borderRadius: 6 }}
        />
        <button
          type="submit"
          style={{ padding: "10px 12px", fontSize: 16, background: "#635DFF", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer" }}
        >
          Continue
        </button>
      </form>

      {error === "not-federated" && (
        <p style={{ marginTop: 16, color: "#b60", fontSize: 14 }}>
          That domain is not an enterprise SSO domain. In a real app this would route to your existing login.
        </p>
      )}

      <p style={{ marginTop: 24, fontSize: 12, color: "#999" }}>
        <a href="/login/client" style={{ color: "#635DFF" }}>
          Client-only variant
        </a>
        {" "}(browser-side startEnterpriseLogin, no server round-trip)
      </p>
    </main>
  );
}
