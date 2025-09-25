/**
 * The default audience to use when none is provided.
 */
export const DEFAULT_AUDIENCE = "default";
/**
 * The default scopes to request when none are provided.
 */
export const DEFAULT_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access"
].join(" ");
