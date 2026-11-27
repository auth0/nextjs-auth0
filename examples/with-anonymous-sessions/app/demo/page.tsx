import Link from "next/link";

import { auth0 } from "@/lib/auth0";
import AnonymousSessionPanel from "@/app/components/AnonymousSessionPanel";
import LoginToLinkButton from "@/app/components/LoginToLinkButton";

export default async function DemoPage() {
  // Server-side anonymous session read (may be stale if access token renewed client-side)
  const anonymousSession = await auth0.getAnonymousSession();

  return (
    <div>
      <h1>Anonymous Session Demo</h1>
      <p>
        <Link href="/">← Back to Home</Link>
      </p>

      <h2>Server-Side Session (SSR)</h2>
      {anonymousSession ? (
        <div className="session-panel">
          <p>
            <strong>ID:</strong> {anonymousSession.id}
          </p>
          <p>
            <strong>Access Token (first 20 chars):</strong>{" "}
            {anonymousSession.accessToken.substring(0, 20)}...
          </p>
          <p>
            <strong>Expires At:</strong>{" "}
            {new Date(anonymousSession.expiresAt * 1000).toISOString()}
          </p>
          {anonymousSession.metadata && (
            <>
              <p>
                <strong>Metadata:</strong>
              </p>
              <pre>{JSON.stringify(anonymousSession.metadata, null, 2)}</pre>
            </>
          )}
          <p style={{ fontSize: "12px", color: "#666", marginTop: "10px" }}>
            Note: SSR data may be stale (D7). Access token renewal is deferred
            to route handlers. Use the client-side panel below for live state.
          </p>
        </div>
      ) : (
        <p>No anonymous session found (server-side read).</p>
      )}

      <h2>Client-Side Session (Live)</h2>
      <AnonymousSessionPanel />

      <h2>Login to Link Session</h2>
      <p>
        Log in to convert this anonymous session into a permanent authenticated
        account. The SDK automatically links the session during the callback.
      </p>
      <LoginToLinkButton />

      <h2>Fetch Protected Resource</h2>
      <p>
        Use the anonymous session access token to call a protected API
        (audience: <code>https://api.customers</code>, scope:{" "}
        <code>read:customers</code>).
      </p>
      <FetchProductsButton />
    </div>
  );
}

function FetchProductsButton() {
  return (
    <form action="/api/products" method="GET">
      <button type="submit">Fetch Products (Protected API)</button>
    </form>
  );
}
