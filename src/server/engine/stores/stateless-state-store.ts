import {
  StatelessStateStore,
  type CookieSerializeOptions,
  type SessionConfiguration,
  type StateData
} from "@auth0/auth0-server-js";
import type { JWTPayload } from "jose";

import type { SessionData } from "../../../types/index.js";
import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import {
  deleteLegacyCookies,
  isLegacyJwe,
  readLegacySession
} from "../legacy/legacy-cookies.js";

// Encrypted session size above which we warn. A large session is the main remaining cause of
// `431 Request Header Fields Too Large`: combined with transaction and application cookies the
// total `Cookie` header can exceed typical 8 KB proxy limits. Same threshold as `main`.
const SESSION_COOKIE_SIZE_WARN_BYTES = 4096;

// Under rolling sessions set() runs on almost every request, so warn once per process.
let sessionSizeWarningEmitted = false;

// The chunk slots `name.0` to `name.4` that every save and delete clears, as `main` did
// (`MAX_CHUNKS`). See `#sweepChunkSlots`.
const CHUNK_SLOTS_SWEPT = 5;

export interface NextStatelessStateStoreOptions extends SessionConfiguration {
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
   * Converts a session read from old-format cookies to the engine shape.
   */
  fromLegacySession: (session: SessionData) => StateData;
}

/**
 * The engine's stateless store, plus:
 * - on read, falls back to old v4 / v3 cookies (and `__FC_*` connection tokens) when the engine
 *   finds no session
 * - on save and delete, deletes every old-format cookie present in the request
 * - warns once per process when the session is large
 */
export class NextStatelessStateStore extends StatelessStateStore<CookieContext> {
  readonly #secret: string;
  readonly #cookieHandler: NextCookieHandler;
  readonly #sessionName: string;
  readonly #deleteOptions: CookieSerializeOptions;
  readonly #fromLegacySession: (session: SessionData) => StateData;

  constructor({
    cookieHandler,
    sessionName,
    deleteOptions,
    fromLegacySession,
    ...options
  }: NextStatelessStateStoreOptions) {
    super(options, cookieHandler);

    this.#secret = options.secret;
    this.#cookieHandler = cookieHandler;
    this.#sessionName = sessionName;
    this.#deleteOptions = deleteOptions;
    this.#fromLegacySession = fromLegacySession;
  }

  override async get(
    identifier: string,
    ctx?: CookieContext
  ): Promise<StateData | undefined> {
    const stateData = await super.get(identifier, ctx);
    if (stateData || !ctx) {
      return stateData;
    }

    const legacySession = await readLegacySession(
      ctx.reqCookies,
      this.#sessionName,
      this.#secret
    );
    return legacySession ? this.#fromLegacySession(legacySession) : undefined;
  }

  override async set(
    identifier: string,
    stateData: StateData,
    removeIfExists?: boolean,
    ctx?: CookieContext
  ): Promise<void> {
    await super.set(identifier, stateData, removeIfExists, ctx);
    this.#sweepChunkSlots(identifier, ctx);
    this.#deleteLegacyCookies(ctx);
  }

  override async delete(
    identifier: string,
    ctx?: CookieContext
  ): Promise<void> {
    await super.delete(identifier, ctx);
    this.#sweepChunkSlots(identifier, ctx);
    this.#deleteLegacyCookies(ctx);
  }

  protected override async encrypt<TData extends JWTPayload>(
    identifier: string,
    stateData: TData,
    expiration: number
  ) {
    const value = await super.encrypt(identifier, stateData, expiration);

    const sessionCookieBytes = new TextEncoder().encode(value).length;
    if (
      sessionCookieBytes >= SESSION_COOKIE_SIZE_WARN_BYTES &&
      !sessionSizeWarningEmitted
    ) {
      sessionSizeWarningEmitted = true;
      console.warn(
        `The ${this.#sessionName} cookie size is ${sessionCookieBytes} bytes, which may ` +
          "exceed request header size limits and cause 431 Request Header Fields Too Large errors " +
          "on some servers, proxies, or CDNs. Consider removing unnecessary custom claims from the " +
          "access token or the user profile, or use a stateful session implementation to store the " +
          "session data in a data store."
      );
    }

    return value;
  }

  /**
   * Treated as no session, as on `main`, where the engine throws:
   * - an expired cookie (`JWTExpired`): the browser can still send one when the cookie is
   *   `transient` (no `Max-Age`)
   * - an old-format JWE (no `kid`) under the engine's chunk names, for example v3 `appSession.N`
   *   when the session name is `appSession`; `get` then falls back to the old-cookie reader
   */
  protected override async decrypt<TData>(
    identifier: string,
    encryptedStateData: string
  ): Promise<TData | undefined> {
    if (isLegacyJwe(encryptedStateData)) {
      return undefined;
    }
    try {
      return await super.decrypt<TData>(identifier, encryptedStateData);
    } catch (e: any) {
      if (e?.code === "ERR_JWT_EXPIRED") {
        return undefined;
      }
      throw e;
    }
  }

  /**
   * Deletes the chunk slots that hold no value after the engine's save or delete, whether or not
   * this request saw them, as `main` did. The engine only deletes the chunks it finds in the
   * request, so a chunk written by a parallel save (two tabs, a bigger session saved a moment
   * earlier) would stay behind, the pieces would no longer join into a valid session, and the user
   * would have to log in again. A slot that was just written holds a value and is skipped.
   */
  #sweepChunkSlots(identifier: string, ctx?: CookieContext): void {
    if (!ctx) {
      return;
    }
    for (let slot = 0; slot < CHUNK_SLOTS_SWEPT; slot++) {
      const name = `${identifier}.${slot}`;
      if (!ctx.reqCookies.get(name)?.value) {
        this.#cookieHandler.deleteCookie(name, ctx, this.#deleteOptions);
      }
    }
  }

  #deleteLegacyCookies(ctx?: CookieContext): void {
    if (!ctx) {
      return;
    }
    deleteLegacyCookies(this.#cookieHandler, ctx, {
      sessionName: this.#sessionName,
      stateful: false,
      deleteOptions: this.#deleteOptions
    });
  }
}
