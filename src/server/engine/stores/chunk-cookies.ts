import type {
  CookieHandler,
  CookieSerializeOptions
} from "@auth0/auth0-server-js";

import { getAllChunkedCookies } from "../../cookies/chunks.js";
import type { CookieContext } from "../context.js";

/**
 * Chunked cookies of the engine's stateless stores, written and cleared the way nextjs did.
 *
 * Used by the stateless session store and the anonymous store.
 */

// The chunks `name__0` to `name__4` that every save and delete clears at least, as on nextjs
// (`MAX_CHUNKS`). See `clearChunks`.
const MAX_CHUNKS = 5;

/**
 * Wraps a cookie handler so that an engine store writes its chunks under nextjs's names.
 *
 * The engine's stateless stores name chunk `i` of `name` as `name.<i>`. This handler stores it as
 * `name__<i>` instead, so the browser holds one chunk family whichever version wrote it: after a
 * rollback, in a rolling deploy or behind a canary, nextjs overwrites and sweeps the same names.
 * Two families side by side make the `Cookie` header about twice the cookie size, which can
 * exceed proxy limits (`431 Request Header Fields Too Large`).
 *
 * - `getCookies()` lists `name__<i>` as `name.<i>`, and hides cookies really named `name.<i>`
 *   (v3 `appSession.<i>` when the session name is `appSession`), so they are never joined into
 *   the value.
 * - Every other cookie name is passed through unchanged.
 */
export function withChunkCookieNames(
  handler: CookieHandler<CookieContext>,
  name: string
): CookieHandler<CookieContext> {
  const enginePrefix = `${name}.`;
  const cookiePrefix = `${name}__`;

  const toCookieName = (key: string): string => {
    const index = chunkIndex(key, enginePrefix);
    return index === undefined ? key : `${cookiePrefix}${index}`;
  };

  return {
    getCookie: (key, ctx) => handler.getCookie(toCookieName(key), ctx),

    getCookies: (ctx) => {
      const result: Record<string, string> = {};
      for (const [key, value] of Object.entries(handler.getCookies(ctx))) {
        if (chunkIndex(key, enginePrefix) !== undefined) {
          continue;
        }
        const index = chunkIndex(key, cookiePrefix);
        result[index === undefined ? key : `${enginePrefix}${index}`] = value;
      }
      return result;
    },

    setCookie: (key, value, options, ctx) =>
      handler.setCookie(toCookieName(key), value, options, ctx),

    deleteCookie: (key, ctx, options) =>
      handler.deleteCookie(toCookieName(key), ctx, options)
  };
}

/**
 * The exclusive upper bound of the chunks to clear, from the request as it arrived:
 * `max(MAX_CHUNKS, highest index seen + 1)`, as `getClearUpTo` on nextjs. Read it before the
 * engine's save or delete changes the request cookies.
 */
export function getClearUpTo(name: string, ctx?: CookieContext): number {
  let highestSeen = -1;
  if (ctx) {
    for (const cookie of getAllChunkedCookies(ctx.reqCookies, name)) {
      highestSeen = Math.max(
        highestSeen,
        Number(cookie.name.slice(name.length + 2))
      );
    }
  }
  return Math.max(MAX_CHUNKS, highestSeen + 1);
}

/**
 * The number of chunks the engine's save just wrote: `name__0` up to the first chunk with no
 * value. Every write is mirrored into the request cookies, and the engine deletes the chunks it
 * did not write.
 */
export function countWrittenChunks(name: string, ctx?: CookieContext): number {
  let count = 0;
  while (ctx?.reqCookies.get(chunkCookieName(name, count))?.value) {
    count++;
  }
  return count;
}

/**
 * Deletes the chunks `name__<from>` to `name__<clearUpTo - 1>` and the unchunked `name`, as
 * `setChunkedCookie` and `deleteChunkedCookie` on nextjs. The engine only deletes the chunks it
 * finds in the request, so a chunk written by a parallel save (two tabs, a bigger value saved a
 * moment earlier) would stay behind, the pieces would no longer join into a valid value, and the
 * user would lose the session. The browser ignores deletes of cookies it does not have.
 *
 * Pass `from` = the chunks just written after a save, `0` after a delete. A name written in this
 * response is never deleted here: the response keeps one entry per cookie name, so the delete would
 * replace the write.
 */
export function clearChunks(
  handler: CookieHandler<CookieContext>,
  ctx: CookieContext | undefined,
  {
    name,
    from,
    clearUpTo,
    deleteOptions
  }: {
    name: string;
    from: number;
    clearUpTo: number;
    deleteOptions: CookieSerializeOptions;
  }
): void {
  if (!ctx) {
    return;
  }
  for (let index = from; index < clearUpTo; index++) {
    handler.deleteCookie(chunkCookieName(name, index), ctx, deleteOptions);
  }
  handler.deleteCookie(name, ctx, deleteOptions);
}

// The cookie name of chunk `index`, as nextjs names it.
function chunkCookieName(name: string, index: number): string {
  return `${name}__${index}`;
}

// The chunk index in `<prefix><index>`, matched as strictly as the engine does (no leading zeros).
function chunkIndex(key: string, prefix: string): string | undefined {
  if (!key.startsWith(prefix)) {
    return undefined;
  }
  const index = key.slice(prefix.length);
  return /^(0|[1-9]\d*)$/.test(index) ? index : undefined;
}
