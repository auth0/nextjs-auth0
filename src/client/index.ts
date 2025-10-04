export { useUser } from "./hooks/use-user.js";
export { getAccessToken } from "./helpers/get-access-token.js";
export {
  withPageAuthRequired,
  WithPageAuthRequired,
  WithPageAuthRequiredOptions
} from "./helpers/with-page-auth-required.js";
export { Auth0Provider } from "./providers/auth0-provider.js";

// DPoP-enabled fetcher exports
export {
  Fetcher,
  fetchWithAuth,
  createFetcher,
  type FetcherConfig,
  type CustomFetchMinimalOutput,
  type CustomFetchImpl,
  type ResponseHeaders
} from "./fetcher/fetcher.js";
