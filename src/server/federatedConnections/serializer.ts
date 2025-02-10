import { SessionData } from "../../types"
import {
  RequestCookies,
  ResponseCookies,
  set,
  SetCookieOptions,
  decrypt,
} from "../cookies"

export const FCAT_AUDIENCE_DEFAULT = "__"
export const FCAT_PREFIX = "__FC"
export const FCAT_DELIMITER = "|"

/**
 * Represents the response containing an access token from a federated connection.
 */
export interface FederatedConnectionTokenSet {
  /**
   * The access token issued by the federated connection.
   */
  accessToken: string
  /**
   * The timestamp (in seconds since epoch) when the access token expires.
   */
  expiresAt: number
  /**
   * Optional. The scope of the access token.
   */
  scope?: string
  /**
   * The name of the federated connection.
   */
  connection: string
}

/**
 * Generates the FCAT cookie name based on the provided provider.
 *
 * @param provider - The name of the provider.
 * @returns The generated FCAT cookie name.
 */
export const getFCCookieName = (provider: string): string => {
  return [FCAT_PREFIX, provider].join(FCAT_DELIMITER)
}

/**
 * Adds or updates a federated token in the session data.
 *
 * @param session - The session data object where the federated token will be added or updated.
 * @param fcat - The federated connection token set containing the access token, expiration time, and scope.
 * @returns The updated session data object.
 */
export const addOrUpdateFederatedTokenToSession = (
  session: SessionData,
  fcat: FederatedConnectionTokenSet
): SessionData => {
  if (!session.federatedConnectionTokenSets) {
    session.federatedConnectionTokenSets = {}
  }

  const serializedFCTokenSet: SerializedFCTokenSet = {
    accessToken: fcat.accessToken,
    expiresAt: fcat.expiresAt,
    scope: fcat.scope,
  }

  if (!session.federatedConnectiontMap) {
    session.federatedConnectiontMap = {}
  }

  session.federatedConnectiontMap[fcat.connection] = serializedFCTokenSet
  return session
}

/**
 * We use a mapping where each provider maps to a set of FCATs.
 */
export type FederatedConnectionMap = {
  [connection: string]: SerializedFCTokenSet
}

export type SerializedFCTokenSet = Omit<
  FederatedConnectionTokenSet,
  "connection"
>

/**
 * Serializes federated tokens and stores them in cookies.
 *
 * @param fcTokenSetMap - A map of federated connection token sets.
 * @param options - Options for storing the tokens in cookies.
 *
 * @returns A promise that resolves when all tokens have been stored in cookies.
 */
export const serializeFederatedTokens = async (
  fcTokenSetMap: FederatedConnectionMap,
  options: SetCookieOptions
): Promise<void> => {
  for (const [key, tokenSet] of Object.entries(fcTokenSetMap)) {
    await set({
      ...options,
      payload: tokenSet,
      cookieName: getFCCookieName(key),
      maxAge: tokenSet.expiresAt,
    })
  }
}

/**
 * Deserializes federated tokens from cookies and returns a map of federated connections.
 *
 * @param cookies - The cookies object, which can be either `RequestCookies` or `ResponseCookies`.
 * @returns A promise that resolves to a `FederatedConnectionMap` containing the deserialized federated tokens.
 */
export const deserializeFederatedTokens = async (
  cookies: RequestCookies | ResponseCookies,
  secret: string
): Promise<FederatedConnectionMap> => {
  /**
   * Represents a mapping for federated connections.
   *
   * @typedef {Object} FCMapping
   * @property {string} provider - The name of the federated provider.
   * @property {SerializedFCTokenSet} tokenSet - The serialized token set associated with the federated connection.
   */
  type FCMapping = {
    provider: string
    tokenSet: SerializedFCTokenSet
  }

  /**
   * Reduces an array of federated connection mappings into a map of token sets.
   *
   * @param acc - The accumulator object that holds the federated connection map.
   * @param param1 - An object containing the provider and token set.
   * @param param1.provider - The provider for the token set.
   * @param param1.tokenSet - The token set to be added to the map.
   * @returns The updated federated connection map with the new token set added.
   */
  const reduceFCKVToTokenSetMap = (
    acc: FederatedConnectionMap,
    { provider, tokenSet }: FCMapping
  ) => {
    acc[provider] = tokenSet
    return acc
  }

  /**
   * Maps a cookie object to an FCMapping object.
   *
   * @param cookie - An object representing a cookie with `name` and `value` properties.
   * @returns An FCMapping object containing the provider and tokenSet.
   *
   * The `name` property of the cookie is expected to be a string with segments separated by `FCAT_DELIMITER`.
   * The first segment is ignored, the second segment is used as the provider.
   * The `value` property of the cookie is parsed as JSON to obtain the tokenSet.
   */
  const cookieToFCKVMapper = async (cookie: {
    name: string
    value: string
  }): Promise<FCMapping> => {
    const [_, provider] = cookie.name.split(FCAT_DELIMITER)
    return {
      provider,
      tokenSet: await decrypt<any>(
        cookie.value,
        secret
      ),
    }
  }

  const allCookies = await Promise.all(cookies
    .getAll() // Get all cookies
    .filter((cookie) => cookie.name.startsWith(FCAT_PREFIX)) // Filter cookies that start with the FCAT prefix
    .map(cookieToFCKVMapper))
    
  return allCookies// Map each cookie to an FCMapping object
    .filter((FCMapping) => !isTokenSetExpired(FCMapping.tokenSet)) // Filter out expired token sets
    .reduce(reduceFCKVToTokenSetMap, {} as FederatedConnectionMap) // Reduce the array of FCMapping objects into a FederatedConnectionMap
}

/**
 * Checks if the given token set is expired.
 *
 * @param tokenSet - The token set to check for expiration.
 * @returns `true` if the token set is expired or not provided, `false` otherwise.
 */
export const isTokenSetExpired = (
  tokenSet: FederatedConnectionTokenSet | SerializedFCTokenSet
): boolean => {
  return !tokenSet || tokenSet.expiresAt <= Date.now()
}

export const findFederatedToken = (
  session: SessionData,
  provider: string
): FederatedConnectionTokenSet | undefined => {
  const partialTokenSet = session.federatedConnectiontMap?.[provider]

  if (partialTokenSet) {
  return {
    ...partialTokenSet,
    connection: provider,
  } as FederatedConnectionTokenSet
  }
}
