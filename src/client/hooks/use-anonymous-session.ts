"use client";

import useSWR from "swr";

import type {
  AnonymousSession,
  UseAnonymousSessionOptions
} from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Fetch the anonymous session from the read route.
 *
 * The route answers 204 with an empty body when there is no session, which maps
 * to null, and 200 with the session object otherwise. Any other status is a
 * failure the hook surfaces through `error`.
 *
 * The return type is declared rather than inferred so the session case is a
 * concrete value rather than the `any` that `Response.json()` produces. That is
 * what keeps `null` from being the only value a reader (human or static analysis)
 * can see the fetcher resolve to.
 */
async function fetchAnonymousSession(
  route: string
): Promise<AnonymousSession | null> {
  const res = await fetch(route);

  if (!res.ok) {
    throw new Error("Failed to load anonymous session");
  }

  // 204 No Content → null (no session)
  if (res.status === 204) {
    return null;
  }

  // 200 + JSON → return session object
  return (await res.json()) as AnonymousSession;
}

/**
 * Client hook: fetch and cache anonymous session via SWR.
 * Mirrors the useUser() pattern.
 *
 * Returns:
 * - anonymous: AnonymousSession | null (null if no session or fetch error)
 * - isLoading: boolean (false when error or data loaded)
 * - error: Error | null (populated on fetch error)
 * - invalidate: () => void (trigger SWR revalidate)
 *
 * Uses SWR key: resolved route (option, env var, or default "/auth/anonymous-session")
 * Fetcher: standard fetch, returns null on 204 status, throws on !ok
 *
 * Test: T7 (hook + provider)
 */
export function useAnonymousSession(options: UseAnonymousSessionOptions = {}): {
  anonymous: AnonymousSession | null;
  isLoading: boolean;
  error: Error | null;
  invalidate: () => void;
} {
  // Resolve SWR key (route path, normalized with basePath)
  const route = normalizeWithBasePath(
    options.route ||
      process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE ||
      "/auth/anonymous-session"
  );

  // Fetch via SWR with standard error handling
  const { data, error, isLoading, mutate } = useSWR<
    AnonymousSession | null,
    Error,
    string
  >(route, fetchAnonymousSession);

  // Return shape matching useUser() pattern
  if (error) {
    return {
      anonymous: null,
      isLoading: false,
      error,
      invalidate: () => mutate()
    };
  }

  // The fetcher resolves to null for a 204, so `data` carries three distinct
  // states: undefined while the first request is in flight, null once the route
  // has answered that there is no session, and the session object otherwise. A
  // truthiness test cannot tell the first two apart, and it reads as a test that
  // can never succeed to a reader that only sees the null-returning branch of the
  // fetcher. Comparing against undefined names the state that is actually being
  // asked about, and every branch below is reachable for some value of `data`.
  const hasLoaded = data !== undefined;

  return {
    anonymous: data ?? null,
    isLoading: hasLoaded ? false : isLoading,
    error: null,
    invalidate: () => mutate()
  };
}
