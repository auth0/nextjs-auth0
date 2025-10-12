export { Auth0Client } from "./client.js";

export { AuthClient } from "./auth-client.js";

export { TransactionStore } from "./transaction-store.js";

export { AbstractSessionStore } from "./session/abstract-session-store.js";

export { filterDefaultIdTokenClaims, DEFAULT_ID_TOKEN_CLAIMS } from "./user.js";

/**
 * Creates a configured server-side fetcher instance with support for base URLs.
 *
 * This is a standalone factory function that provides the same functionality as
 * Auth0Client.createFetcher() but with a more explicit API.
 *
 * @param auth0Client - The Auth0Client instance to use for authentication
 * @param config - Configuration options for the fetcher
 * @returns A configured fetcher instance
 *
 * @example
 * ```typescript
 * import { auth0 } from '@/lib/auth0';
 * import { createFetcher } from '@auth0/nextjs-auth0/server';
 *
 * const apiFetcher = createFetcher(auth0, {
 *   baseUrl: 'https://api.example.com'
 * });
 * const response = await apiFetcher.fetchWithAuth('/users/profile');
 * ```
 */
export function createFetcher(
  auth0Client: { createFetcher: (config?: { baseUrl?: string }) => any },
  config: { baseUrl?: string } = {}
) {
  return auth0Client.createFetcher(config);
}

export {
  GetServerSidePropsResultWithSession,
  WithPageAuthRequired,
  WithPageAuthRequiredPageRouterOptions,
  WithPageAuthRequiredAppRouterOptions,
  PageRoute,
  AppRouterPageRouteOpts,
  AppRouterPageRoute,
  WithPageAuthRequiredPageRouter,
  WithPageAuthRequiredAppRouter
} from "./helpers/with-page-auth-required.js";
