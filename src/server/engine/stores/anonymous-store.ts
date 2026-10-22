import {
  StatelessAnonymousStore,
  type AnonymousStateData,
  type CookieSerializeOptions,
  type StatelessAnonymousStoreOptions
} from "@auth0/auth0-server-js";

import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import { isLegacyJwe } from "../legacy/legacy-cookies.js";
import {
  clearChunks,
  countWrittenChunks,
  getClearUpTo,
  withChunkCookieNames
} from "./chunk-cookies.js";

export interface NextAnonymousStoreOptions extends StatelessAnonymousStoreOptions {
  cookieHandler: NextCookieHandler;
  /**
   * The anonymous cookie name (`anonymousSession.cookie.name`, default `auth0_anon`).
   */
  name: string;
  /**
   * Attributes used to delete anonymous cookies (`httpOnly`, `secure`, `sameSite`, `path`).
   */
  deleteOptions: CookieSerializeOptions;
}

/**
 * The engine's anonymous store, plus:
 * - writes the chunks under nextjs's names, `name__0`, `name__1`, ... (see `withChunkCookieNames`)
 * - on save and delete, clears the unused chunks and the unchunked `name` the way nextjs did.
 *   Create, renew, logout, clear on login and a session Auth0 says is gone all end in `set` or
 *   `delete`, so nextjs's own `name` / `name__N` cookies also go at the first of them. A plain
 *   read leaves them alone.
 */
export class NextAnonymousStore extends StatelessAnonymousStore<CookieContext> {
  readonly #cookieHandler: NextCookieHandler;
  readonly #name: string;
  readonly #deleteOptions: CookieSerializeOptions;

  constructor({
    cookieHandler,
    name,
    deleteOptions,
    ...options
  }: NextAnonymousStoreOptions) {
    super(options, withChunkCookieNames(cookieHandler, name));

    this.#cookieHandler = cookieHandler;
    this.#name = name;
    this.#deleteOptions = deleteOptions;
  }

  override async set(
    identifier: string,
    anonymousStateData: AnonymousStateData,
    removeIfExists?: boolean,
    ctx?: CookieContext
  ): Promise<void> {
    const clearUpTo = getClearUpTo(this.#name, ctx);
    await super.set(identifier, anonymousStateData, removeIfExists, ctx);
    this.#clearChunks(countWrittenChunks(this.#name, ctx), clearUpTo, ctx);
  }

  override async delete(
    identifier: string,
    ctx?: CookieContext
  ): Promise<void> {
    const clearUpTo = getClearUpTo(this.#name, ctx);
    await super.delete(identifier, ctx);
    this.#clearChunks(0, clearUpTo, ctx);
  }

  /**
   * nextjs's anonymous cookie (a JWE without `kid`, in `name__N`, which are also the engine's chunk
   * names here) is treated as no anonymous session, where the engine throws. It is not read: the
   * visitor gets a new anonymous session once.
   */
  protected override async decrypt<TData>(
    identifier: string,
    encryptedStateData: string
  ): Promise<TData | undefined> {
    if (isLegacyJwe(encryptedStateData)) {
      return undefined;
    }
    return super.decrypt<TData>(identifier, encryptedStateData);
  }

  #clearChunks(from: number, clearUpTo: number, ctx?: CookieContext): void {
    clearChunks(this.#cookieHandler, ctx, {
      name: this.#name,
      from,
      clearUpTo,
      deleteOptions: this.#deleteOptions
    });
  }
}
