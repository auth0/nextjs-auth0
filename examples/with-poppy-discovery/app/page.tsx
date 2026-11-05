import { auth0 } from "@/lib/auth0";

import { Inspector } from "./inspector";

export default async function Home() {
  const poppy = await auth0.getPoppyContext();
  const session = await auth0.getSession();

  return (
    <>
      <h1>Poppy</h1>
      <p className="subtitle">
        Let personal AI agents shop on your site, and tell them apart from
        people.
      </p>

      <section className="card">
        <h2>Who&apos;s driving</h2>
        {poppy.kind === "agent" ? (
          <span className="badge badge-agent">
            Agent · {poppy.state === "guest" ? "guest" : "signed in"}
          </span>
        ) : (
          <span className="badge badge-human">Person</span>
        )}

        <dl>
          {poppy.kind === "agent" && (
            <>
              <dt>Agent</dt>
              <dd>{poppy.agent.clientId}</dd>
              <dt>Poppy session</dt>
              <dd>{poppy.poppy_sid}</dd>
              <dt>Scopes</dt>
              <dd>{poppy.scopes.join(" ") || "none"}</dd>
            </>
          )}
          <dt>Customer</dt>
          <dd>{session ? (session.user.email ?? session.user.sub) : "not signed in"}</dd>
        </dl>

        <div className="actions">
          {session ? (
            <a className="button" href="/auth/logout">
              Log out
            </a>
          ) : (
            <a className="button" href="/auth/login">
              Log in
            </a>
          )}
          <a className="button button-secondary" href="/cart">
            View cart
          </a>
        </div>
      </section>

      <section className="card">
        <h2>Try the methods</h2>
        <p>
          Each button calls the SDK on the server and shows what it returns for
          your browser.
        </p>
        <Inspector />
      </section>

      <section className="card">
        <h2>Discovery files</h2>
        <p>The SDK serves these for agents, built from auth0-poppy.json:</p>
        <ul>
          <li>
            <a href="/.well-known/poppy.json">/.well-known/poppy.json</a>
          </li>
          <li>
            <a href="/.well-known/oauth-protected-resource">
              /.well-known/oauth-protected-resource
            </a>
          </li>
        </ul>
      </section>
    </>
  );
}
