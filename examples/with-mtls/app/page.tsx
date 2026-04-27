import { auth0 } from "@/lib/auth0";

/**
 * Home page — demonstrates the mTLS-authenticated session and token.
 *
 * Because this is a React Server Component, we can call `auth0.getSession()`
 * and `auth0.getAccessToken()` directly without an extra API route.
 *
 * The access token returned by Auth0 will contain a `cnf.x5t#S256` claim
 * binding it to the client certificate — your resource server can verify
 * this claim to enforce certificate-bound token usage (RFC 8705 §3).
 */
export default async function Home() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <h1>Auth0 mTLS Example</h1>
        <p>
          You are not signed in.{" "}
          <a href="/auth/login">Sign in with Auth0</a>
        </p>
        <p>
          This example uses{" "}
          <strong>Mutual TLS (RFC 8705)</strong> for client authentication.
          The Auth0 SDK authenticates with a client certificate instead of a
          client secret, and all issued access tokens are certificate-bound.
        </p>
      </main>
    );
  }

  // Retrieve the (certificate-bound) access token.
  // Requires offline_access scope + a refresh token in the session.
  let tokenInfo: { token: string; expiresAt: number } | null = null;
  let tokenError: string | null = null;
  try {
    tokenInfo = await auth0.getAccessToken();
  } catch (err) {
    tokenError = err instanceof Error ? err.message : String(err);
  }

  const { user } = session;

  return (
    <main>
      <h1>Auth0 mTLS Example</h1>

      <p>
        Signed in as <strong>{user.name ?? user.email ?? user.sub}</strong>.{" "}
        <a href="/auth/logout">Sign out</a>
      </p>

      <h2 style={{ marginTop: "1.5rem", marginBottom: "0.5rem" }}>Session</h2>
      <pre>{JSON.stringify({ user }, null, 2)}</pre>

      <h2 style={{ marginTop: "1.5rem", marginBottom: "0.5rem" }}>
        Access Token{" "}
        <span className="badge badge-green" title="Certificate-bound">
          mTLS-bound
        </span>
      </h2>
      {tokenError ? (
        <p style={{ color: "red" }}>Error: {tokenError}</p>
      ) : tokenInfo ? (
        <>
          <pre>{tokenInfo.token}</pre>
          <p>
            Expires at: {new Date(tokenInfo.expiresAt * 1000).toISOString()}
          </p>
          <p>
            <span className="badge badge-blue">💡 Tip</span> Decode the token
            at{" "}
            <a href="https://jwt.io" target="_blank" rel="noopener noreferrer">
              jwt.io
            </a>{" "}
            and look for the <code>cnf.x5t#S256</code> claim — it contains the
            SHA-256 thumbprint of your client certificate, binding the token
            to your TLS identity.
          </p>
        </>
      ) : null}
    </main>
  );
}
