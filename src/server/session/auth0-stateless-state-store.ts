import {
  StatelessStateStore,
  type CookieHandler,
  type EncryptedStoreOptions,
  type SessionConfiguration,
  type StateData
} from "@auth0/auth0-server-js";

import type { Auth0CookieContext } from "../auth-client/auth0-cookie-handler.js";
import type { RequestCookies } from "../cookies/index.js";
import {
  buildLegacyDeleteOptions,
  cleanupLegacyStatelessCookies,
  LegacyCookieDeleteOptions,
  LegacyCookieOverrides,
  readLegacyStatelessStateData
} from "./legacy-cookie-compat.js";

// Total encoded session-cookie size (across all native `__session.N` chunks)
// above which we warn. Matches the threshold and rationale of the warning in
// the v4 `stateless-session-store.ts`: an oversized session is the main
// remaining cause of `431 Request Header Fields Too Large`, and — unlike
// transaction cookies — the session is never evicted.
const SESSION_COOKIE_SIZE_WARN_BYTES = 4096;

// Emit the size warning once per process. Under rolling sessions `set()` runs on
// ~every authenticated request, so a legitimately large session would otherwise
// log on every request.
let sessionSizeWarningEmitted = false;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Stateless state store on top of auth0-server-js. Writes the native
 * A256CBC-HS512 format under the existing cookie name (via the engine's own
 * `set()`), and adds the seamless migration read + old-format cleanup that the
 * engine base does not provide:
 *
 * - `get`: native `${identifier}.N` first, then legacy v4 (`name` / `name__N`,
 *   A256GCM) and v3 (`appSession` / `appSession.N`), mapped into `StateData`.
 *   The engine's own `get()` cannot read either legacy shape: it assembles by
 *   splitting on `.` (so v4 `name__N` yields a `NaN` index and misorders) and
 *   only collects keys that `startsWith(identifier)` (so v3 `appSession` is
 *   never gathered).
 * - `set`: delegate to the engine for the native write and its `startsWith`
 *   cleanup (which removes v4 `name__N` and the bare `name`), then explicitly
 *   clean the differently-named v3 `appSession` (+ `appSession.N`).
 * - `delete`: engine delete (native + v4 + bare) plus v3 `appSession` cleanup.
 *
 * Connection token sets (`__FC_*`) are intentionally not handled here; they stay
 * owned by the connected-accounts code, and the mapper never populates
 * `StateData.connectionTokenSets`.
 */
export class Auth0StatelessStateStore extends StatelessStateStore<Auth0CookieContext> {
  readonly #legacyDeleteOptions: LegacyCookieDeleteOptions;

  constructor(
    options: SessionConfiguration & EncryptedStoreOptions,
    cookieHandler: CookieHandler<Auth0CookieContext>,
    legacyCookieOptions?: LegacyCookieOverrides
  ) {
    super(options, cookieHandler);
    this.#legacyDeleteOptions = buildLegacyDeleteOptions(
      options.cookie,
      legacyCookieOptions
    );
  }

  override async get(
    identifier: string,
    options?: Auth0CookieContext
  ): Promise<StateData | undefined> {
    const reqCookies = options?.reqCookies;

    // No request cookies (should not happen in nextjs-auth0's call sites): defer
    // to the engine's native-only read.
    if (!reqCookies) {
      return super.get(identifier, options);
    }

    // 1) Native A256CBC-HS512 under `${identifier}.N` (what we write now).
    const native = await this.#getNative(identifier, reqCookies);
    if (native) {
      return native;
    }

    // 2) Legacy v4 then v3, mapped into StateData. Never throws; unreadable ->
    //    undefined (anonymous / fresh login). Reads never rewrite.
    return readLegacyStatelessStateData(
      reqCookies,
      identifier,
      this.options.secret
    );
  }

  override async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: Auth0CookieContext
  ): Promise<void> {
    // Native write + engine cleanup: the engine chunks `${identifier}.N` and
    // removes any existing cookie whose name `startsWith(identifier)` and is not
    // one of the new chunks — that clears the bare v4 `__session` and the v4
    // `__session__N` chunks in place.
    await super.set(identifier, stateData, removeIfExists, options);

    const reqCookies = options?.reqCookies;
    const resCookies = options?.resCookies;
    if (!reqCookies || !resCookies) {
      return;
    }

    // The v3 `appSession` (+ `appSession.N`) is a different name, so the engine's
    // `startsWith(identifier)` sweep never touches it. Clean it explicitly.
    cleanupLegacyStatelessCookies(
      reqCookies,
      resCookies,
      this.#legacyDeleteOptions
    );

    this.#warnIfSessionCookieLarge(identifier, reqCookies);
  }

  override async delete(
    identifier: string,
    options?: Auth0CookieContext
  ): Promise<void> {
    // Engine delete removes every cookie that `startsWith(identifier)`: native
    // `${identifier}.N`, v4 `${identifier}__N`, and the bare name.
    await super.delete(identifier, options);

    const reqCookies = options?.reqCookies;
    const resCookies = options?.resCookies;
    if (!reqCookies || !resCookies) {
      return;
    }

    // Plus the differently-named v3 `appSession`.
    cleanupLegacyStatelessCookies(
      reqCookies,
      resCookies,
      this.#legacyDeleteOptions
    );
  }

  /**
   * Reads and decrypts the native `${identifier}.N` chunks only. Uses a strict
   * `^${identifier}\.\d+$` match (so v4 `${identifier}__N` and the bare name are
   * excluded) and the engine's own `decrypt` for the native A256CBC-HS512
   * format. Returns `undefined` when no native chunks are present.
   */
  async #getNative(
    identifier: string,
    reqCookies: RequestCookies
  ): Promise<StateData | undefined> {
    const indexRegex = new RegExp(`^${escapeRegExp(identifier)}\\.(\\d+)$`);

    const chunks = reqCookies
      .getAll()
      .map((cookie) => {
        const match = indexRegex.exec(cookie.name);
        return match
          ? { index: parseInt(match[1], 10), value: cookie.value }
          : null;
      })
      .filter(
        (chunk): chunk is { index: number; value: string } => chunk !== null
      )
      .sort((a, b) => a.index - b.index);

    if (chunks.length === 0) {
      return undefined;
    }

    const joined = chunks.map((chunk) => chunk.value).join("");

    // `this.decrypt` (engine, protected) returns `undefined` on a decryption
    // failure and only rethrows genuine faults.
    return this.decrypt<StateData>(identifier, joined);
  }

  #warnIfSessionCookieLarge(
    identifier: string,
    reqCookies: RequestCookies
  ): void {
    if (sessionSizeWarningEmitted) {
      return;
    }

    const indexRegex = new RegExp(`^${escapeRegExp(identifier)}\\.\\d+$`);
    const encoder = new TextEncoder();
    let totalBytes = 0;
    for (const cookie of reqCookies.getAll()) {
      if (indexRegex.test(cookie.name)) {
        totalBytes += encoder.encode(`${cookie.name}=${cookie.value}`).length;
      }
    }

    if (totalBytes >= SESSION_COOKIE_SIZE_WARN_BYTES) {
      sessionSizeWarningEmitted = true;
      console.warn(
        `The ${identifier} cookie size is ${totalBytes} bytes, which may ` +
          "exceed request header size limits and cause 431 Request Header Fields Too Large errors " +
          "on some servers, proxies, or CDNs. Consider removing unnecessary custom claims from the " +
          "access token or the user profile, or use a stateful session implementation to store the " +
          "session data in a data store."
      );
    }
  }
}
