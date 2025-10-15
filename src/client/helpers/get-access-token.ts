import { AccessTokenError } from "../../errors/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Options for fetching an access token.
 *
 * **Important for Multi-API Applications**: When your application calls multiple APIs with different
 * audiences, you **must** specify the `audience` parameter to ensure the correct access token is retrieved.
 * Without specifying the audience, the default access token from the session will be used, which may be
 * intended for a different API.
 *
 * @example
 * ```typescript
 * // Single API - no audience needed (uses session token)
 * const token = await getAccessToken();
 *
 * // Multi-API - specify audience for correct token
 * const profileToken = await getAccessToken({
 *   audience: 'https://profile-api.example.com'
 * });
 * const ordersToken = await getAccessToken({
 *   audience: 'https://orders-api.example.com'
 * });
 * ```
 */
export type AccessTokenOptions = {
  /**
   * Additional scopes to request beyond those granted during login.
   * Requires the Auth0 Application to be configured for Multi-Resource Refresh Tokens (MRRT).
   *
   * @example 'read:profile write:profile'
   */
  scope?: string;

  /**
   * The unique identifier of the target API. This should match the API identifier configured in Auth0.
   *
   * **Critical for Multi-API Applications**: If your application calls multiple APIs, you must specify
   * this parameter to ensure the correct access token is used for each API. Each API requires its own
   * access token with the appropriate audience.
   *
   * **Configuration Requirement**: When using `audience` or `scope`, ensure that the audiences and scopes
   * are part of your Auth0 Application's Refresh Token Policies. This requires configuring
   * Multi-Resource Refresh Tokens (MRRT) in your Auth0 Application settings.
   *
   * @see https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token - Multi-Resource Refresh Tokens documentation
   *
   * @example 'https://api.example.com'
   * @example 'https://orders-api.mycompany.com'
   */
  audience?: string;
};

type AccessTokenResponse = {
  token: string;
  scope?: string;
  expires_at?: number;
  token_type?: string;
};

/**
 * Fetches an access token for the currently logged-in user.
 * @param options Options for fetching the access token, including optional audience and scope.
 * @returns The access token as a string.
 * @note Passing audience or scope relies on MRRT to be configured in your Auth0 Application.
 * @see https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token/configure-and-implement-multi-resource-refresh-token
 */
export async function getAccessToken(
  options: AccessTokenOptions = {}
): Promise<string> {
  const urlParams = new URLSearchParams();

  // We only want to add the audience if it's explicitly provided
  if (options.audience) {
    urlParams.append("audience", options.audience);
  }

  // We only want to add the scope if it's explicitly provided
  if (options.scope) {
    urlParams.append("scope", options.scope);
  }

  let url = normalizeWithBasePath(
    process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token"
  );

  // Only append the query string if we have any url parameters to add
  if (urlParams.size > 0) {
    url = url + `?${urlParams.toString()}`;
  }

  const tokenRes = await fetch(url);

  if (!tokenRes.ok) {
    // try to parse it as JSON and throw the error from the API
    // otherwise, throw a generic error
    let accessTokenError;
    try {
      accessTokenError = await tokenRes.json();
    } catch (e) {
      throw new Error(
        "An unexpected error occurred while trying to fetch the access token."
      );
    }

    throw new AccessTokenError(
      accessTokenError.error.code,
      accessTokenError.error.message
    );
  }

  const tokenSet: AccessTokenResponse = await tokenRes.json();
  return tokenSet.token;
}
