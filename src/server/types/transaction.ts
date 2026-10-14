import type * as jose from "jose";

import type { RESPONSE_TYPES } from "../../types/index.js";

export interface TransactionState extends jose.JWTPayload {
  codeVerifier?: string;
  responseType: RESPONSE_TYPES;
  state: string; // the state parameter passed to the authorization server
  returnTo: string; // the URL to redirect to after login
  nonce?: string; // A string value used to associate a client session with an ID Token, and to mitigate replay attacks.  codeVerifier: string;
  maxAge?: number; // the maximum age of the authentication session
  authSession?: string; // the auth session ID for connect accounts
  /**
   * The scope requested for this transaction.
   */
  scope?: string;

  /**
   * The audience used for this transaction.
   */
  audience?: string;

  /**
   * The challenge mode for this transaction.
   * - 'redirect' (default): Standard OAuth redirect flow
   * - 'popup': Popup flow returning via window.postMessage
   */
  challengeMode?: "redirect" | "popup";

  /**
   * The Auth0 domain used for this transaction (MCD mode).
   * Stored to validate that the session is for the same domain.
   * @internal
   */
  originDomain?: string;

  /**
   * The OIDC issuer URL for this transaction (MCD mode).
   * Stored alongside originDomain for validation.
   * @internal
   */
  originIssuer?: string;

  /**
   * True when a transfer ticket was successfully minted and appended to /authorize
   * (link attempted, not confirmed — Auth0 may silently discard expired or replayed
   * tickets). Indicates to the onCallback hook that post-login migration logic may apply.
   */
  anonymousSessionLinked?: boolean;

  /**
   * SHA-256 digest, hex encoded, of the anonymous session token that was
   * injected into this login transaction. The raw token is never stored here.
   * The callback recomputes the digest from the anonymous cookie it receives and
   * refuses to report a link when the two do not match, which is what binds the
   * linkage signal to the browser that started the transaction.
   *
   * Absent on transactions created before this field existed, and on
   * transactions where no anonymous session was injected. Both cases are treated
   * as unbound rather than as a mismatch.
   * @internal
   */
  anonymousSessionRef?: string;
}

export interface TransactionCookieOptions {
  /**
   * The prefix of the cookie used to store the transaction state.
   *
   * Default: `__txn_{state}`.
   */
  prefix?: string;
  /**
   * The sameSite attribute of the transaction cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none";
  /**
   * The secure attribute of the transaction cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
  /**
   * The path attribute of the transaction cookie. Will be set to '/' by default.
   */
  path?: string;
  /**
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3 | Domain Set-Cookie attribute}. By default, no
   * domain is set, and most clients will consider the cookie to apply to only
   * the current domain.
   */
  domain?: string;
  /**
   * The expiration time for transaction cookies in seconds.
   * If not provided, defaults to 1 hour (3600 seconds).
   *
   * @default 3600
   */
  maxAge?: number;
}

export interface TransactionStoreOptions {
  secret: string;
  cookieOptions?: TransactionCookieOptions;
  /**
   * Controls whether multiple parallel login transactions are allowed.
   * When false, only one transaction cookie is maintained at a time.
   * When true (default), multiple transaction cookies can coexist for multi-tab support.
   *
   * @default true
   */
  enableParallelTransactions?: boolean;
}
