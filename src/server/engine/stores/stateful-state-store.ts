import {
  StatefulStateStore,
  type CookieSerializeOptions,
  type SessionConfiguration,
  type SessionStore,
  type StateData
} from "@auth0/auth0-server-js";

import type { SessionData, SessionDataStore } from "../../../types/index.js";
import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import {
  decryptLegacySessionId,
  deleteLegacyCookies,
  isLegacyJwe,
  readV3SessionId
} from "../legacy/legacy-cookies.js";
import { normalizeStatefulSession } from "../legacy/normalize-session.js";

export interface NextStatefulStateStoreOptions extends SessionConfiguration {
  secret: string;
  cookieHandler: NextCookieHandler;
  /**
   * The session cookie name (`session.cookie.name`, default `__session`).
   */
  sessionName: string;
  /**
   * Attributes used to delete old-format cookies (`domain`, `path`, `secure`, `sameSite`, `httpOnly`).
   */
  deleteOptions: CookieSerializeOptions;
  /**
   * The consumer's session store. Rows keep today's `SessionData` shape.
   */
  store: SessionDataStore;
  /**
   * Converts a row read from the consumer's store to the engine shape.
   */
  toStateData: (session: SessionData) => StateData;
  /**
   * Converts engine session data to the row shape written to the consumer's store.
   */
  toSessionData: (stateData: StateData) => SessionData;
}

/**
 * Presents the consumer's `SessionDataStore` as an engine `SessionStore`, converting rows on the
 * way in and out. `update` is only exposed when the consumer implements it, so the engine falls
 * back to `get` + `set` otherwise.
 */
function toEngineStore(
  store: SessionDataStore,
  toStateData: (session: SessionData) => StateData,
  toSessionData: (stateData: StateData) => SessionData
): SessionStore<CookieContext> {
  const engineStore: SessionStore<CookieContext> = {
    async get(id) {
      const session = await store.get(id);
      return session
        ? toStateData(normalizeStatefulSession(session))
        : undefined;
    },
    set(id, stateData) {
      return store.set(id, toSessionData(stateData));
    },
    delete(id) {
      return store.delete(id);
    },
    deleteByLogoutToken(claims) {
      if (!store.deleteByLogoutToken) {
        // The back-channel logout route checks for this before calling.
        throw new Error(
          "The session store does not implement deleteByLogoutToken."
        );
      }
      return store.deleteByLogoutToken(claims);
    }
  };

  if (store.update) {
    const update = store.update.bind(store);
    engineStore.update = (id, stateData) =>
      update(id, toSessionData(stateData));
  }

  return engineStore;
}

/**
 * The engine's stateful store, connected to the consumer's `SessionDataStore`, plus:
 * - reads old v4 ID cookies (same name, JWE without `kid`) in place, keeping the session ID
 * - on read, falls back to old v3 signed ID cookies when the engine finds no session
 * - on save and delete, deletes the old v3 row and every old-format cookie present in the request
 * - `deleteByReqCookies`: deletes the row without touching cookies (session ceiling reached)
 */
export class NextStatefulStateStore extends StatefulStateStore<CookieContext> {
  readonly #secret: string;
  readonly #cookieHandler: NextCookieHandler;
  readonly #sessionName: string;
  readonly #deleteOptions: CookieSerializeOptions;
  readonly #store: SessionDataStore;
  readonly #engineStore: SessionStore<CookieContext>;

  constructor({
    cookieHandler,
    sessionName,
    deleteOptions,
    store,
    toStateData,
    toSessionData,
    ...options
  }: NextStatefulStateStoreOptions) {
    const engineStore = toEngineStore(store, toStateData, toSessionData);
    super({ ...options, store: engineStore }, cookieHandler);

    this.#secret = options.secret;
    this.#cookieHandler = cookieHandler;
    this.#sessionName = sessionName;
    this.#deleteOptions = deleteOptions;
    this.#store = store;
    this.#engineStore = engineStore;
  }

  override async get(
    identifier: string,
    ctx?: CookieContext
  ): Promise<StateData | undefined> {
    const stateData = await super.get(identifier, ctx);
    if (stateData || !ctx) {
      return stateData;
    }

    const v3SessionId = await this.#readV3SessionId(ctx);
    return v3SessionId ? this.#engineStore.get(v3SessionId) : undefined;
  }

  override async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    ctx?: CookieContext
  ): Promise<void> {
    // Read before super.set: the cookie handler mirrors the new cookie into the request cookies.
    const v3SessionId = await this.#readV3SessionId(ctx);

    // The new ID cookie may not reach the browser (read-only call, or a Server Component where
    // the write fails). The browser keeps the v3 cookie, so update the v3 row in place, as `main`
    // does, instead of moving the session to a new ID and deleting the row it points to.
    if (v3SessionId && !removeIfExists && !canWriteCookies(ctx)) {
      await this.#updateRow(v3SessionId, stateData);
      return;
    }

    await super.set(identifier, stateData, removeIfExists, ctx);
    await this.#deleteLegacy(v3SessionId, ctx);
  }

  override async delete(
    identifier: string,
    ctx?: CookieContext
  ): Promise<void> {
    const v3SessionId = await this.#readV3SessionId(ctx);
    await super.delete(identifier, ctx);
    await this.#deleteLegacy(v3SessionId, ctx);
  }

  /**
   * Deletes the session row (and a v3 row) found from the request cookies, without writing or
   * deleting any cookie. Used when the session ceiling is reached on a read, as on `main`.
   */
  deleteByReqCookies(
    identifier: string,
    reqCookies: CookieContext["reqCookies"]
  ): Promise<void> {
    // Without `resCookies` the cookie handler skips every cookie delete.
    return this.delete(identifier, { reqCookies });
  }

  /**
   * A v4 ID cookie is a JWE without `kid`, which the engine cannot decrypt (it throws instead of
   * returning nothing). Decrypt it the v4 way and hand the ID to the engine.
   *
   * An expired cookie is treated as no session, as on `main`; the engine throws `JWTExpired`.
   * The browser can still send one when the cookie is `transient` (no `Max-Age`).
   */
  protected override async decrypt<TData>(
    identifier: string,
    encryptedStateData: string
  ): Promise<TData | undefined> {
    if (!isLegacyJwe(encryptedStateData)) {
      try {
        return await super.decrypt<TData>(identifier, encryptedStateData);
      } catch (e: any) {
        if (e?.code === "ERR_JWT_EXPIRED") {
          return undefined;
        }
        throw e;
      }
    }

    const id = await decryptLegacySessionId(encryptedStateData, this.#secret);
    return id ? ({ id } as TData) : undefined;
  }

  // Same rolling race guard as the engine: never re-create a row deleted by a concurrent logout.
  async #updateRow(id: string, stateData: StateData): Promise<void> {
    if (this.#engineStore.update) {
      await this.#engineStore.update(id, stateData);
    } else if (await this.#engineStore.get(id)) {
      await this.#engineStore.set(id, stateData);
    }
  }

  #readV3SessionId(ctx?: CookieContext): Promise<string | null> {
    if (!ctx) {
      return Promise.resolve(null);
    }
    return readV3SessionId(ctx.reqCookies, this.#sessionName, this.#secret);
  }

  async #deleteLegacy(
    v3SessionId: string | null,
    ctx?: CookieContext
  ): Promise<void> {
    if (!ctx) {
      return;
    }
    // The engine never reads the v3 cookie, so the v3 row is never reused: delete it.
    if (v3SessionId) {
      await this.#store.delete(v3SessionId);
    }
    deleteLegacyCookies(this.#cookieHandler, ctx, {
      sessionName: this.#sessionName,
      stateful: true,
      deleteOptions: this.#deleteOptions
    });
  }
}

function canWriteCookies(ctx?: CookieContext): boolean {
  return !!ctx?.resCookies && !ctx.ignoreWriteErrors;
}
