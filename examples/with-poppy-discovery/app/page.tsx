import { auth0 } from "@/lib/auth0";

import { BrowserContext } from "./browser-context";
import { Inspector } from "./inspector";

// What getSession() and getAnonymousSession() return for each kind of visitor.
const BEHAVIOUR = [
  {
    key: "nobody",
    who: "No one logged in",
    session: "null",
    anonymous: "null"
  },
  {
    key: "person",
    who: "A person, logged in",
    session: "the person's session",
    anonymous: "null"
  },
  {
    key: "guest",
    who: "An agent, signed out (guest)",
    session: "null",
    anonymous: "the guest: id and expiresAt (the access token stays on the server)"
  },
  {
    key: "signed_in",
    who: "An agent, signed in",
    session: "the customer's session",
    anonymous: "null"
  }
] as const;

export default async function Home() {
  const poppy = await auth0.poppy.getContext();
  const session = await auth0.getSession();

  // Which row of the table describes this browser right now.
  const current =
    poppy.kind === "agent"
      ? poppy.state === "guest"
        ? "guest"
        : "signed_in"
      : session
        ? "person"
        : "nobody";

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
              <dd>{poppy.act.sub}</dd>
              <dt>Poppy session</dt>
              <dd>{poppy.act.poppy_sid}</dd>
              <dt>Token subject</dt>
              <dd>{poppy.sub}</dd>
              <dt>Scopes</dt>
              <dd>{poppy.scopes.join(" ") || "none"}</dd>
            </>
          )}
          <dt>Customer</dt>
          <dd>{session ? (session.user.email ?? session.user.sub) : "not signed in"}</dd>
        </dl>

        <div className="actions">
          {session || poppy.kind === "agent" ? (
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
        <h2>1. Poppy: auth0.poppy.getContext()</h2>
        <p>
          The new Poppy method. It says who is driving this browser: a person,
          or an agent, and for an agent whether it is a guest or signed in.
          For an agent it mirrors the ID token: the token&apos;s own{" "}
          <code>sub</code> and <code>sub_profile</code>, and the whole{" "}
          <code>act</code> claim. The second button asks the same in the
          browser, through <code>/auth/poppy-context</code>.
        </p>
        <Inspector calls={["poppy.getContext"]} />
        <BrowserContext />
      </section>

      <section className="card">
        <h2>2. Existing: getSession() and getAnonymousSession()</h2>
        <p>
          These SDK methods were there before Poppy. Which one has a value
          depends on who is driving. Click both: each result stays on the page.
        </p>
        <Inspector calls={["getSession", "getAnonymousSession"]} />

        <p className="result-title">What each one returns</p>
        <table className="behaviour">
          <thead>
            <tr>
              <th>Who is driving</th>
              <th>getSession()</th>
              <th>getAnonymousSession()</th>
            </tr>
          </thead>
          <tbody>
            {BEHAVIOUR.map((row) => (
              <tr
                key={row.key}
                className={row.key === current ? "current" : undefined}
              >
                <td>
                  {row.who}
                  {row.key === current && <strong> · this browser</strong>}
                </td>
                <td>{row.session}</td>
                <td>{row.anonymous}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
