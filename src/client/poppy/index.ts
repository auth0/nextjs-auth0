import { PoppyError, PoppyErrorCode } from "../../errors/index.js";
import type { PoppyBrowserClient, PoppyContext } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

class ClientPoppyClient implements PoppyBrowserClient {
  async getContext(): Promise<PoppyContext> {
    const url = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_POPPY_CONTEXT_ROUTE || "/auth/poppy-context"
    );

    let res: Response;
    try {
      res = await fetch(url, { credentials: "same-origin", cache: "no-store" });
    } catch (err: any) {
      throw new PoppyError(
        PoppyErrorCode.CONTEXT_UNAVAILABLE,
        `The Poppy context could not be read: ${err?.message ?? "network error"}.`
      );
    }

    if (res.status === 404) {
      throw new PoppyError(PoppyErrorCode.NOT_ENABLED);
    }
    if (!res.ok) {
      throw new PoppyError(
        PoppyErrorCode.CONTEXT_UNAVAILABLE,
        `The Poppy context could not be read (HTTP ${res.status}).`
      );
    }

    try {
      return (await res.json()) as PoppyContext;
    } catch {
      throw new PoppyError(
        PoppyErrorCode.CONTEXT_UNAVAILABLE,
        "The Poppy context route did not return JSON."
      );
    }
  }
}

/**
 * Client-side Poppy (Personal Agent Protocol) singleton. Experimental and
 * subject to change.
 *
 * Prefer `auth0.poppy.getContext()` in a Server Component, and pass what the
 * page needs to client components as props. Use this when only the browser
 * has the information it needs.
 *
 * @example
 * ```tsx
 * "use client";
 * import { poppy } from "@auth0/nextjs-auth0";
 *
 * const context = await poppy.getContext();
 * if (context.kind === "agent") {
 *   showBanner(`Browsing via ${context.agent.clientId} (${context.state})`);
 * }
 * ```
 *
 * @category Session
 */
export const poppy: PoppyBrowserClient = new ClientPoppyClient();
