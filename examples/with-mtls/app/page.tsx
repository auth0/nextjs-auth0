"use server";

import { auth0 } from "@/lib/auth0";
import { RefreshButton } from "./refresh-button";

async function forceRefresh() {
  "use server";
  let tokenInfo;
  try {
    tokenInfo = await auth0.getAccessToken({ refresh: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  if (!tokenInfo) return { error: "No token returned" };
  const parts = tokenInfo.token.split(".");
  let payload: Record<string, unknown> | null = null;
  if (parts.length === 3) {
    try { payload = JSON.parse(Buffer.from(parts[1], "base64url").toString()); } catch {}
  }
  const cnf = (payload as any)?.cnf?.["x5t#S256"] ?? null;
  return { token: tokenInfo.token, expiresAt: tokenInfo.expiresAt, payload, cnf };
}

export default async function Home() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <h1>Auth0 mTLS Example</h1>
        <p>You are not signed in. <a href="/auth/login">Sign in with Auth0</a></p>
      </main>
    );
  }

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

      <h2 style={{ marginTop: "1.5rem", marginBottom: "0.5rem" }}>Access Token</h2>
      {tokenError ? (
        <p style={{ color: "red" }}>Error: {tokenError}</p>
      ) : tokenInfo ? (
        <>
          <pre style={{ wordBreak: "break-all" }}>{tokenInfo.token}</pre>
          <p>Expires at: {new Date(tokenInfo.expiresAt * 1000).toISOString()}</p>
        </>
      ) : null}

      <h2 style={{ marginTop: "1.5rem", marginBottom: "0.5rem" }}>
        Refresh Token (<code>grant_type=refresh_token</code> via mTLS alias)
      </h2>
      <RefreshButton refreshAction={forceRefresh} />
    </main>
  );
}
