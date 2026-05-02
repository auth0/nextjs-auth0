export { useUser, type UseUserOptions } from "./hooks/use-user.js";
export {
  getAccessToken,
  type AccessTokenOptions
} from "./helpers/get-access-token.js";
export {
  withPageAuthRequired,
  WithPageAuthRequired,
  WithPageAuthRequiredOptions
} from "./helpers/with-page-auth-required.js";
export {
  Auth0Provider,
  type Auth0ProviderProps
} from "./providers/auth0-provider.js";
export { mfa } from "./mfa/index.js";
export type { ChallengeWithPopupOptions } from "./mfa/index.js";
export type { AccessTokenResponse } from "./helpers/get-access-token.js";
