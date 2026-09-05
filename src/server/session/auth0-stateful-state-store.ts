import {
  StatefulStateStore,
  type CookieHandler,
  type EncryptedStoreOptions,
  type LogoutTokenClaims,
  type SessionConfiguration,
  type SessionStore,
  type StateData
} from "@auth0/auth0-server-js";

import type { SessionDataStore } from "../../types/index.js";
import type { Auth0CookieContext } from "../auth-client/auth0-cookie-handler.js";
import {
  deleteCookie,
  RequestCookies,
  ResponseCookies
} from "../cookies/index.js";
import {
  buildLegacyDeleteOptions,
  LegacyCookieDeleteOptions,
  LegacyCookieOverrides,
  readLegacyStatefulSessionId
} from "./legacy-cookie-compat.js";
import {
  LEGACY_COOKIE_NAME,
  normalizeStatefulSession
} from "./normalize-session.js";
import {
  sessionDataToStateData,
  stateDataToSessionData
} from "./session-mapper.js";

const generateId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

export interface Auth0StatefulStateStoreOptions
  extends EncryptedStoreOptions, SessionConfiguration {
  /**
   * The nextjs-auth0 `SessionDataStore` supplied by the consumer. It persists
   * and returns nextjs-auth0 `SessionData` (the shipped public contract); this
   * class maps `StateData` <-> `SessionData` around it.
   */
  store: SessionDataStore;
}

/**
 * Stateful state store on top of auth0-server-js. The cookie holds only the
 * encrypted session-ID pointer; the session body lives in the consumer's
 * `SessionDataStore`. Writes the native format under the existing cookie name,
 * and adds seamless migration reads the engine base cannot do (its
 * `getSessionId` is private, single-name, and JWE-only):
 *
 * - `get` / `delete` / `set` resolve the session ID across native, v4 JWE
 *   `{id}`, and v3 HMAC-signed values, under both the configured name and the
 *   v3 `appSession` name.
 * - `set` preserves an existing session ID across the migration (no orphaned
 *   store rows, no re-login) and keeps the v4 rolling-update race guard when the
 *   store exposes `update`.
 * - The engine works in `StateData`, but the consumer's `SessionDataStore`
 *   persists nextjs-auth0 `SessionData`. This class owns that mapping directly
 *   (via `session-mapper`): `set`/`update` convert `StateData` -> `SessionData`
 *   before writing, and `get` normalizes any pre-migration legacy row
 *   (`normalizeStatefulSession`) then converts `SessionData` -> `StateData`. The
 *   stored contents therefore stay in the exact shape the current v4
 *   `StatefulSessionStore` writes, so existing store rows keep working.
 */
export class Auth0StatefulStateStore extends StatefulStateStore<Auth0CookieContext> {
  // The consumer's store, holding nextjs-auth0 `SessionData` (not engine
  // `StateData`). We map at every boundary below.
  readonly #store: SessionDataStore;
  readonly #legacyDeleteOptions: LegacyCookieDeleteOptions;

  constructor(
    options: Auth0StatefulStateStoreOptions,
    cookieHandler: CookieHandler<Auth0CookieContext>,
    legacyCookieOptions?: LegacyCookieOverrides
  ) {
    // The engine base keeps its own private `#store` and reads it only inside
    // `set`/`get`/`delete`/`deleteByLogoutToken`, all of which we fully override,
    // so the value handed to `super` is never touched at runtime. We hold the
    // consumer's `SessionDataStore` directly (below) and do the `SessionData`
    // <-> `StateData` mapping ourselves.
    super(
      {
        ...options,
        store: options.store as unknown as SessionStore<Auth0CookieContext>
      },
      cookieHandler
    );
    this.#store = options.store;
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
    if (!reqCookies) {
      return undefined;
    }

    const sessionId = await this.#resolveSessionId(identifier, reqCookies);
    if (!sessionId) {
      return undefined;
    }

    const stored = await this.#store.get(sessionId);

    // Cookie present but the store row is gone -> clear the stale cookie(s).
    if (!stored) {
      if (options?.resCookies) {
        this.#deleteCookies(identifier, reqCookies, options.resCookies);
      }
      return undefined;
    }

    // Normalize a pre-migration (v3) row into `SessionData`, then map into the
    // engine's `StateData`.
    return sessionDataToStateData(normalizeStatefulSession(stored));
  }

  override async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    options?: Auth0CookieContext
  ): Promise<void> {
    const reqCookies = options?.reqCookies;
    const resCookies = options?.resCookies;

    // Reuse an existing session ID (native, v4, or v3-signed) so a migrating
    // user keeps their store row and session-fixation continuity; otherwise mint
    // a fresh one.
    let sessionId = reqCookies
      ? await this.#resolveSessionId(identifier, reqCookies)
      : undefined;

    // New login (removeIfExists): drop the old row and regenerate the ID to
    // prevent session fixation.
    if (sessionId && removeIfExists) {
      await this.#store.delete(sessionId);
      sessionId = generateId();
    }

    const existingSessionId = !removeIfExists && sessionId ? sessionId : null;
    sessionId ??= generateId();

    // The engine hands us `StateData`; the consumer's store persists nextjs-auth0
    // `SessionData`. Map before writing so stored rows keep the exact shape the
    // v4 `StatefulSessionStore` produced. A `StateData` with no user/token set
    // cannot be represented as a `SessionData` and is nothing worth persisting.
    const sessionData = stateDataToSessionData(stateData);
    if (!sessionData) {
      return;
    }

    // Rolling-update race guard (only when updating an existing session): a
    // concurrent logout may have deleted the row; without this check the
    // in-flight rolling response would re-create it. Use the store's atomic
    // `update` when available, else a non-atomic get()+set().
    if (existingSessionId !== null) {
      if (typeof this.#store.update === "function") {
        const updated = await this.#store.update(
          existingSessionId,
          sessionData
        );
        if (!updated) {
          return;
        }
      } else {
        const existing = await this.#store.get(existingSessionId);
        if (!existing) {
          return;
        }
        await this.#store.set(existingSessionId, sessionData);
      }
    } else {
      await this.#store.set(sessionId, sessionData);
    }

    // Server Component path (no response cookies): store is updated but the
    // pointer cookie cannot be (re)written.
    if (!resCookies || !reqCookies) {
      return;
    }

    const maxAge = this.calculateMaxAge(
      stateData.internal.createdAt,
      stateData.sessionExpiresAt
    );
    const expiration = Math.floor(Date.now() / 1000) + maxAge;
    const encrypted = await this.encrypt<{ id: string }>(
      identifier,
      { id: sessionId },
      expiration
    );

    resCookies.set(identifier, encrypted, {
      ...this.#cookieAttributes(),
      maxAge
    });
    // read-after-write in the same request (middleware)
    reqCookies.set(identifier, encrypted);

    // Once the native pointer is written, drop the v3 `appSession` pointer
    // (stateful is a single cookie, no chunking).
    if (
      identifier !== LEGACY_COOKIE_NAME &&
      reqCookies.has(LEGACY_COOKIE_NAME)
    ) {
      deleteCookie(resCookies, LEGACY_COOKIE_NAME, this.#legacyDeleteOptions);
      reqCookies.delete(LEGACY_COOKIE_NAME);
    }
  }

  override async delete(
    identifier: string,
    options?: Auth0CookieContext
  ): Promise<void> {
    const reqCookies = options?.reqCookies;
    const resCookies = options?.resCookies;

    if (reqCookies) {
      const sessionId = await this.#resolveSessionId(identifier, reqCookies);
      if (sessionId) {
        await this.#store.delete(sessionId);
      }
      if (resCookies) {
        this.#deleteCookies(identifier, reqCookies, resCookies);
      }
    }
  }

  override async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
    // `SessionDataStore.deleteByLogoutToken` is optional and takes the same
    // `{ sub, sid, iss }` shape (nextjs-auth0 `LogoutToken` is structurally the
    // engine's `LogoutTokenClaims`). No-op when the consumer's store does not
    // implement it, matching the v4 back-channel-logout behavior.
    if (typeof this.#store.deleteByLogoutToken === "function") {
      await this.#store.deleteByLogoutToken(claims);
    }
  }

  /**
   * Resolves the session ID from the cookie across all three formats: native
   * `{id}` under `identifier`, then v4 JWE `{id}` / v3 HMAC-signed under
   * `identifier` or the v3 `appSession` name.
   */
  async #resolveSessionId(
    identifier: string,
    reqCookies: RequestCookies
  ): Promise<string | undefined> {
    const nativeValue = reqCookies.get(identifier)?.value;
    if (nativeValue) {
      try {
        const native = await this.decrypt<{ id: string }>(
          identifier,
          nativeValue
        );
        if (native?.id) {
          return native.id;
        }
      } catch {
        // Not a native cookie (a v4/v3 value under the same name, or expired) —
        // fall through to the legacy resolution below.
      }
    }

    return readLegacyStatefulSessionId(
      reqCookies,
      identifier,
      this.options.secret
    );
  }

  #deleteCookies(
    identifier: string,
    reqCookies: RequestCookies,
    resCookies: ResponseCookies
  ): void {
    deleteCookie(resCookies, identifier, this.#legacyDeleteOptions);
    reqCookies.delete(identifier);

    if (
      identifier !== LEGACY_COOKIE_NAME &&
      reqCookies.has(LEGACY_COOKIE_NAME)
    ) {
      deleteCookie(resCookies, LEGACY_COOKIE_NAME, this.#legacyDeleteOptions);
      reqCookies.delete(LEGACY_COOKIE_NAME);
    }
  }

  #cookieAttributes() {
    return {
      httpOnly: this.#legacyDeleteOptions.httpOnly ?? true,
      sameSite: this.#legacyDeleteOptions.sameSite ?? "lax",
      path: this.#legacyDeleteOptions.path ?? "/",
      secure: this.#legacyDeleteOptions.secure ?? true,
      ...(this.#legacyDeleteOptions.domain
        ? { domain: this.#legacyDeleteOptions.domain }
        : {})
    };
  }
}
