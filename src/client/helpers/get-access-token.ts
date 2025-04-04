import { AccessTokenError } from "../../errors/index.js";

export async function getAccessToken() {
  const tokenRes = await fetch(
    process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token"
  );

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

  const tokenSet = await tokenRes.json();
  return tokenSet.token;
}
