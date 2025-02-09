import { SessionData } from "../../types"
import {
  RequestCookies,
  ResponseCookies,
  set,
  SetCookieOptions,
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
 * Generates the FCAT cookie name based on the provided provider and optional audience.
 *
 * @param provider - The name of the provider.
 * @param audience - The optional audience. If not provided, a default audience will be used.
 * @returns The generated FCAT cookie name.
 */
export const getFCCookieName = (
  provider: string,
  audience?: string
): string => {
  return [FCAT_PREFIX, provider, audience ?? FCAT_AUDIENCE_DEFAULT].join(
    FCAT_DELIMITER
  )
}

/**
 * Adds or updates a federated token in the session data.
 *
 * @param session - The session data object where the federated token will be added or updated.
 * @param audience - The audience for the federated token. If undefined, a default audience will be used.
 * @param fcat - The federated connection token set containing the access token, expiration time, and scope.
 * @returns The updated session data object.
 */
export const addOrUpdateFederatedTokenToSession = (
  session: SessionData,
  audience: string | undefined,
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

  const audienceKey = audience ?? FCAT_AUDIENCE_DEFAULT
  if (!session.federatedConnectiontMap) {
    session.federatedConnectiontMap = {}
  }

  if (!session.federatedConnectiontMap[fcat.connection]) {
    session.federatedConnectiontMap[fcat.connection] = {}
  }
  session.federatedConnectiontMap[fcat.connection][audienceKey] =
    serializedFCTokenSet
  return session
}

/**
 * We use a nested mapping where each provider maps to a set of FCATs keyed by audience.
 * If no audience is provided, use '__' as the key.
 */
export type FederatedConnectionMap = {
  [connection: string]: {
    // Use audience key; when none, default to '__'
    [audience: string]: SerializedFCTokenSet
  }
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
 * @param audience - The audience for which the tokens are intended.
 *
 * @returns A promise that resolves when all tokens have been stored in cookies.
 */
export const serializeFederatedTokens = async (
  fcTokenSetMap: FederatedConnectionMap,
  options: SetCookieOptions,
  audience: string | undefined
): Promise<void> => {
  for (const [key, tokenSet] of Object.entries(fcTokenSetMap)) {
    await set({
      ...options,
      payload: tokenSet[audience ?? FCAT_AUDIENCE_DEFAULT],
      cookieName: getFCCookieName(key, audience),
      maxAge: tokenSet[audience ?? FCAT_AUDIENCE_DEFAULT].expiresAt,
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
  cookies: RequestCookies | ResponseCookies
): Promise<FederatedConnectionMap> => {
  /**
   * Represents a mapping for federated connections.
   *
   * @typedef {Object} FCMapping
   * @property {string} provider - The name of the federated provider.
   * @property {string} audience - The audience for the federated connection.
   * @property {SerializedFCTokenSet} tokenSet - The serialized token set associated with the federated connection.
   */
  type FCMapping = {
    provider: string
    audience: string
    tokenSet: SerializedFCTokenSet
  }

  /**
   * Reduces an array of federated connection mappings into a map of token sets.
   *
   * @param acc - The accumulator object that holds the federated connection map.
   * @param param1 - An object containing the audience, provider, and token set.
   * @param param1.audience - The audience for the token set.
   * @param param1.provider - The provider for the token set.
   * @param param1.tokenSet - The token set to be added to the map.
   * @returns The updated federated connection map with the new token set added.
   */
  const reduceFCKVToTokenSetMap = (
    acc: FederatedConnectionMap,
    { audience, provider, tokenSet }: FCMapping
  ) => {
    acc[provider] ??= {}
    acc[provider][audience ?? FCAT_AUDIENCE_DEFAULT] = tokenSet
    return acc
  }

  /**
   * Maps a cookie object to an FCMapping object.
   *
   * @param cookie - An object representing a cookie with `name` and `value` properties.
   * @returns An FCMapping object containing the provider, audience, and tokenSet.
   *
   * The `name` property of the cookie is expected to be a string with segments separated by `FCAT_DELIMITER`.
   * The first segment is ignored, the second segment is used as the provider, and the third segment (if present) is used as the audience.
   * If the audience segment is not present, `FCAT_AUDIENCE_DEFAULT` is used as the default audience.
   * The `value` property of the cookie is parsed as JSON to obtain the tokenSet.
   */
  const cookieToFCKVMapper = (cookie: {
    name: string
    value: string
  }): FCMapping => {
    const [_, provider, audience] = cookie.name.split(FCAT_DELIMITER)
    return {
      provider,
      audience: audience ?? FCAT_AUDIENCE_DEFAULT,
      tokenSet: JSON.parse(cookie.value),
    }
  }

  return cookies
    .getAll() // Get all cookies
    .filter((cookie) => cookie.name.startsWith(FCAT_PREFIX)) // Filter cookies that start with the FCAT prefix
    .map(cookieToFCKVMapper) // Map each cookie to an FCMapping object
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

export const findFederatedToken = (session: SessionData, provider: string, audience?: string): FederatedConnectionTokenSet | undefined => {
  const audienceKey = audience ?? FCAT_AUDIENCE_DEFAULT
  const partialTokenSet = session.federatedConnectiontMap?.[provider]?.[audienceKey]
  return {...partialTokenSet, connection: provider} as FederatedConnectionTokenSet
}