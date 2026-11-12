/** Fixed by the Poppy spec and RFC 9728, so not configurable like `routes`. */
export const POPPY_DISCOVERY_PATH = "/.well-known/poppy.json";
export const PROTECTED_RESOURCE_METADATA_PATH =
  "/.well-known/oauth-protected-resource";

/**
 * The `act` claims that make a login a Personal Agent's. Auth0's browser join
 * always sends them; an impersonation `act` has only `sub`.
 */
export const POPPY_REQUIRED_ACT_CLAIMS = [
  "sub",
  "poppy_sid",
  "poppy_user_id"
] as const;

/** The guest subject format of the current Auth0 PoC (test plan SO-03). */
export const DEFAULT_POPPY_GUEST_SUBJECT_PREFIX = "anon_poppy@";

/**
 * The `sub_profile` value on an anonymous subject's tokens. A guest join's
 * tokens carry `sub_profile: "user urn:auth0:anonymous_user"`.
 */
export const ANONYMOUS_SUB_PROFILE = "urn:auth0:anonymous_user";
