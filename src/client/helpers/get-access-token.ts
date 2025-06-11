import { AccessTokenError } from "../../errors";

type AccessTokenResponse = {
  token: string;
  scope?: string;
  expires_at?: number;
};

export type GetAccessTokenOptions = {
  /**
   * Force a refresh of the access token.
   */
  refresh?: boolean;
};

/**
 * Retrieves an access token from the `/auth/access-token` endpoint.
 *
 * @returns The access token string.
 * @throws {AccessTokenError} If there's an error retrieving the access token.
 */
export async function getAccessToken(): Promise<string>;

/**
 * Retrieves an access token from the `/auth/access-token` endpoint.
 *
 * @param options Configuration for getting the access token.
 * @returns The access token string.
 * @throws {AccessTokenError} If there's an error retrieving the access token.
 */
export async function getAccessToken(
  options: GetAccessTokenOptions
): Promise<string>;

/**
 * Retrieves an access token from the `/auth/access-token` endpoint.
 *
 * @param options Optional configuration for getting the access token.
 * @returns The access token string.
 * @throws {AccessTokenError} If there's an error retrieving the access token.
 */
export async function getAccessToken(
  options?: GetAccessTokenOptions
): Promise<string> {
  const searchParams = new URLSearchParams();
  if (options?.refresh) {
    searchParams.set("refresh", "true");
  }

  const baseUrl = `${process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE}` || "/auth/access-token";
  const queryParams = searchParams.toString() ? `?${searchParams.toString()}` : "";
  const url = `${baseUrl}${queryParams}`;

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
