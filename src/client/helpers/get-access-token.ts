import { AccessTokenError } from "../../errors/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

export type AccessTokenOptions = {
  scope?: string;
  /**
   * If you are passing audience, ensure that the used audiences and scopes are
   * part of the Application's Refresh Token Policies in Auth0 when configuring Multi-Resource Refresh Tokens (MRRT).
   * {@link https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token|See Auth0 Documentation on Multi-resource Refresh Tokens}
   *
   */
  audience?: string;
};

type AccessTokenResponse = {
  token: string;
  scope?: string;
  expires_at?: number;
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
