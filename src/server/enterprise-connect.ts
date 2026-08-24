import { InvalidConfigurationError } from "../errors/index.js";

/**
 * Methods on {@link Auth0Client} that remain available when
 * `enterpriseConnect: true` is set. Everything else on the prototype is blocked.
 *
 * Adding a new method that should work in EC mode means adding it here.
 */
export const EC_ALLOWED_METHODS = new Set([
  "middleware",
  "startInteractiveLogin",
  "startEnterpriseLogin",
  "customTokenExchange",
]);

/**
 * Getters on {@link Auth0Client} that remain available when
 * `enterpriseConnect: true` is set.
 */
export const EC_ALLOWED_GETTERS = new Set<string>();

/**
 * Optional per-member guidance appended to the thrown error message.
 * When absent the error carries only the generic "not available" message.
 */
export const EC_MEMBER_GUIDANCE: Record<string, string> = {
  getSession:
    "Auth0 does not hold a session in this mode. Read the user from the session " +
    "store you populated in onCallback.",
  getAccessToken:
    "Enterprise Connect clients are not issued refresh tokens, so there is no token " +
    "to return or renew. Use the tokens passed to onCallback if you need to call " +
    "an API on the user's behalf.",
  getAccessTokenForConnection:
    "This reads the token set from an Auth0 session, which does not exist in this " +
    "mode. Store connection tokens yourself from the onCallback session if needed.",
  revokeRefreshToken:
    "Enterprise Connect clients are not issued refresh tokens, so there is nothing " +
    "to revoke.",
  requestSessionTransferToken:
    "Session transfer reads and refreshes an Auth0 session, which does not exist " +
    "in this mode.",
  updateSession:
    "There is no Auth0 session cookie to update in this mode. Write to your own " +
    "session store instead.",
  connectAccount:
    "Connecting an account requires an existing Auth0 session, which is not " +
    "created in this mode.",
  createFetcher:
    "The fetcher attaches an access token read from an Auth0 session, which does " +
    "not exist in this mode. Pass your own token to fetch directly.",
  buildSessionTransferRedirect:
    "Session transfer requires an existing Auth0 session to transfer, which is not " +
    "created in this mode.",
  getTokenByBackchannelAuth:
    "CIBA requires the auth_req_id from /bc-authorize to be held between requests, " +
    "and Enterprise Connect stores no transaction state across them.",
  passwordless:
    "Passwordless establishes an Auth0 session, which conflicts with this mode. " +
    "Authentication must go through the enterprise IdP via /auth/login.",
  passkey:
    "Passkeys establish an Auth0 session, which conflicts with this mode. " +
    "Authentication must go through the enterprise IdP via /auth/login.",
  mfa:
    "MFA requires Auth0 to manage authentication state across requests, which " +
    "does not exist in this mode. MFA must be handled by the enterprise IdP."
};

/**
 * Methods that are synchronous (non-Promise return type) and must throw rather
 * than reject — rejecting would contradict the signature and escape try/catch.
 */
export const EC_SYNC_METHODS = new Set(["buildSessionTransferRedirect"]);

/**
 * Walks the prototype of `instance` and replaces every method and getter NOT in
 * the allowlist with one that throws {@link InvalidConfigurationError}.
 *
 * Note: because the replacements are own properties on the instance, they shadow
 * internal `this.<member>()` calls. A member that stays available must not read
 * the session via `this.getSession()` — use the private `getSessionFromAuthClient`
 * helper, which is never shadowed.
 */
export function applyEnterpriseConnectRestrictions(instance: object): void {
  const proto = Object.getPrototypeOf(instance);
  for (const [name, desc] of Object.entries(
    Object.getOwnPropertyDescriptors(proto)
  )) {
    if (name === "constructor") continue;

    const guidance = EC_MEMBER_GUIDANCE[name] ?? "";
    const suffix = guidance ? ` ${guidance}` : "";

    if (desc.get) {
      if (!EC_ALLOWED_GETTERS.has(name)) {
        Object.defineProperty(instance, name, {
          configurable: true,
          enumerable: false,
          get: () => {
            throw new InvalidConfigurationError(
              `${name} is not available when enterpriseConnect is true.${suffix}`
            );
          }
        });
      }
    } else if (typeof desc.value === "function") {
      if (!EC_ALLOWED_METHODS.has(name)) {
        const label = `${name}()`;
        const error = () =>
          new InvalidConfigurationError(
            `${label} is not available when enterpriseConnect is true.${suffix}`
          );
        Object.defineProperty(instance, name, {
          configurable: true,
          enumerable: false,
          writable: true,
          // Sync methods throw; async methods reject so await/catch works.
          value: EC_SYNC_METHODS.has(name)
            ? () => { throw error(); }
            : () => Promise.reject(error())
        });
      }
    }
  }
}
