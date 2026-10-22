import {
  StatelessAnonymousStore,
  type AnonymousStateData,
  type CookieSerializeOptions,
  type StatelessAnonymousStoreOptions
} from "@auth0/auth0-server-js";

import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import { deleteLegacyAnonymousCookies } from "../legacy/legacy-cookies.js";

export interface NextAnonymousStoreOptions extends StatelessAnonymousStoreOptions {
  cookieHandler: NextCookieHandler;
  /**
   * The anonymous cookie name (`anonymousSession.cookie.name`, default `auth0_anon`).
   */
  name: string;
  /**
   * Attributes used to delete `main`'s anonymous cookies (`httpOnly`, `secure`, `sameSite`, `path`).
   */
  deleteOptions: CookieSerializeOptions;
}

/**
 * The engine's anonymous store, plus: on save and on delete, deletes `main`'s anonymous cookies
 * (`name` and `name__N`) present in the request. Create, renew, logout, clear on login and a
 * session Auth0 says is gone all end in `set` or `delete`, so the old cookies go at the first of
 * them. A plain read leaves them alone.
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
    super(options, cookieHandler);

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
    await super.set(identifier, anonymousStateData, removeIfExists, ctx);
    this.#deleteLegacyCookies(ctx);
  }

  override async delete(
    identifier: string,
    ctx?: CookieContext
  ): Promise<void> {
    await super.delete(identifier, ctx);
    this.#deleteLegacyCookies(ctx);
  }

  #deleteLegacyCookies(ctx?: CookieContext): void {
    if (!ctx) {
      return;
    }
    deleteLegacyAnonymousCookies(this.#cookieHandler, ctx, {
      name: this.#name,
      deleteOptions: this.#deleteOptions
    });
  }
}
