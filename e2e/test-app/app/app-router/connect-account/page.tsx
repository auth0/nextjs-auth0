import { auth0 } from "@/lib/auth0";

// Shows connect-account status. The connectAccount() call is driven by the
// /auth/connect route handler (built into the SDK middleware). This page
// just confirms the user's session for after the flow completes.
export default async function ConnectAccountPage() {
  const session = await auth0.getSession();

  if (!session) {
    return (
      <main>
        <h1 id="status">unauthenticated</h1>
        <a href="/auth/login?returnTo=/app-router/connect-account">Log in</a>
      </main>
    );
  }

  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="email">{session.user.email}</p>
      {/* Link to initiate connect-account — SDK's /auth/connect handler redirects to Auth0 */}
      <a id="connect-link" href="/auth/connect?connection=google-oauth2&returnTo=/app-router/connect-account">
        Connect Google account
      </a>
    </main>
  );
}
