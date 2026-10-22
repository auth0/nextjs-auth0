import { createTimeoutFetch } from "@auth0/auth0-server-js";

/**
 * `fetchImpl` with the app's `httpTimeout` on each request, for the requests the SDK makes itself (the
 * Fetcher, the proxy, the My Account passkey calls). Requests made by the engine get `httpTimeout` from
 * the engine. Returns `fetchImpl` as is when `httpTimeout` is not set; `null` from an untyped caller
 * counts as not set, as `??` did on nextjs.
 */
export function withHttpTimeout<
  F extends (...args: never[]) => Promise<Response>
>(fetchImpl: F, httpTimeout: number | null | undefined): F {
  return httpTimeout == null
    ? fetchImpl
    : (createTimeoutFetch(
        fetchImpl as unknown as typeof fetch,
        httpTimeout
      ) as unknown as F);
}
