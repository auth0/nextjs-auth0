import { auth0 } from "@/lib/auth0";

// Opens only with a signed-in session. Without one, withPageAuthRequired sends
// the browser to /auth/login?returnTo=/protected. An agent guest has no
// session, and Auth0 answers that login with the same guest again. The SDK
// refuses it (poppy_sign_in_required) after one round trip, so opening this
// page as a guest shows that error instead of a redirect loop.
export default auth0.withPageAuthRequired(
  async function Protected() {
    const session = await auth0.getSession();
    const poppy = await auth0.poppy.getContext();

    return (
      <>
        <h1>Protected page</h1>
        <p className="subtitle">
          <a href="/">← Back</a>
        </p>

        <section className="card">
          <h2>Session</h2>
          <dl>
            <dt>Customer</dt>
            <dd>{session?.user.email ?? session?.user.sub}</dd>
          </dl>
        </section>

        <section className="card">
          <h2>auth0.poppy.getContext()</h2>
          <pre>{JSON.stringify(poppy, null, 2)}</pre>
        </section>
      </>
    );
  },
  { returnTo: "/protected" }
);
