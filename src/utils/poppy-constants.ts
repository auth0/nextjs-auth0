/** The only Poppy protocol version this SDK supports. */
export const POPPY_PROTOCOL_VERSION = "0.3";

/** Fixed by the Poppy spec and RFC 9728, so not configurable like `routes`. */
export const POPPY_DISCOVERY_PATH = "/.well-known/poppy.json";
export const PROTECTED_RESOURCE_METADATA_PATH =
  "/.well-known/oauth-protected-resource";

/**
 * The claims inside `act` that Auth0's browser join puts in the web app's ID
 * and access tokens. The SDK exposes them under the same names, so there is
 * one name for each value.
 */
export const POPPY_SESSION_ID_CLAIM = "poppy_sid";
export const POPPY_USER_ID_CLAIM = "poppy_user_id";
export const POPPY_AGENT_ID_CLAIM = "poppy_agent_id";

/** The guest subject format of the current Auth0 PoC (test plan SO-03). */
export const DEFAULT_POPPY_GUEST_SUBJECT_PREFIX = "anon_poppy@";

/**
 * The `sub_profile` value on an anonymous subject's tokens. A guest join's
 * tokens carry `sub_profile: "user urn:auth0:anonymous_user"`.
 */
export const ANONYMOUS_SUB_PROFILE = "urn:auth0:anonymous_user";
