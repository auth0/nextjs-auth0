import type { NextRequest } from "next/server.js";

import type { PoppyContext } from "../types/poppy.js";
import type { PagesRouterRequest } from "./client.js";

/**
 * Server-side Poppy (Personal Agent Protocol) API, available as
 * `auth0.poppy`. Beta and subject to change.
 *
 * @example App Router
 * ```ts
 * const poppy = await auth0.poppy.getContext();
 * if (poppy.kind === "agent") {
 *   // act.sub is the agent: its Auth0 agent ID, or its client metadata URL.
 *   await saveOrder(cart, { placedVia: poppy.act.sub });
 * }
 * ```
 *
 * @category Session
 */
export class ServerPoppyClient {
  /** @internal */
  constructor(
    private readonly resolveContext: (
      req?: Request | PagesRouterRequest | NextRequest
    ) => Promise<PoppyContext>
  ) {}

  /**
   * getContext says who is driving the current request: a person, or a
   * Personal Agent as a guest or signed in to the customer's account.
   *
   * Always `{ kind: "human" }` when the `poppy` option is not set. Mirrors
   * `getSession()`, and throws what it throws.
   *
   * Use in Server Components, Server Actions, and Route Handlers in the **App Router**.
   */
  async getContext(): Promise<PoppyContext>;

  /**
   * getContext says who is driving the current request.
   *
   * Use in middleware and `getServerSideProps`, API routes in the **Pages Router**.
   */
  async getContext(
    req: PagesRouterRequest | NextRequest
  ): Promise<PoppyContext>;

  async getContext(
    req?: Request | PagesRouterRequest | NextRequest
  ): Promise<PoppyContext> {
    return this.resolveContext(req);
  }
}
