import { auth0 } from "@/lib/auth0";

export default async function Cart() {
  const poppy = await auth0.getPoppyContext();
  const session = await auth0.getSession();

  // Key the cart by the Poppy session for an agent. A guest agent and the same
  // agent after the customer signs in share it, so the cart carries over.
  const owner =
    poppy.kind === "agent"
      ? `${poppy.agent.clientId} · ${poppy.poppy_sid}`
      : (session?.user.email ?? session?.user.sub ?? "anonymous visitor");

  return (
    <>
      <h1>Cart</h1>
      <p className="subtitle">
        <a href="/">← Back</a>
      </p>

      <section className="card">
        <h2>This cart belongs to</h2>
        <dl>
          <dt>{poppy.kind === "agent" ? "Agent session" : "Customer"}</dt>
          <dd>{owner}</dd>
        </dl>
      </section>
    </>
  );
}
