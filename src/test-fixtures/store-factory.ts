import { Auth0CookieHandler } from "../server/auth-client/auth0-cookie-handler.js";
import {
  AbstractSessionStore,
  type SessionConfiguration,
  type SessionCookieOptions
} from "../server/session/abstract-session-store.js";
import { Auth0StatefulStateStore } from "../server/session/auth0-stateful-state-store.js";
import { Auth0StatelessStateStore } from "../server/session/auth0-stateless-state-store.js";
import {
  Auth0TransactionStore,
  DEFAULT_TRANSACTION_COOKIE_PREFIX
} from "../server/session/auth0-transaction-store.js";
import type { LegacyCookieOverrides } from "../server/session/legacy-cookie-compat.js";
import { StatefulSessionStore } from "../server/session/stateful-session-store.js";
import { StatelessSessionStore } from "../server/session/stateless-session-store.js";
import type { TransactionCookieOptions } from "../server/transaction-store.js";
import type { SessionDataStore } from "../types/index.js";

/**
 * Options for {@link createTestStores}. Everything except `secret` is optional
 * and mirrors the corresponding `Auth0Client` constructor inputs, so a test can
 * express any store configuration it previously built by hand.
 */
export interface CreateTestStoresOptions {
  secret: string;
  /**
   * Session configuration (rolling, durations, `beforeSessionRolled`, cookie),
   * matching the consumer-facing `options.session` in `client.ts`.
   */
  session?: SessionConfiguration;
  /**
   * Session cookie overrides. Merged on top of `session.cookie`; takes
   * precedence, exactly as the explicit resolution in `client.ts` does.
   */
  sessionCookieOptions?: SessionCookieOptions;
  /**
   * Transaction cookie overrides (prefix, sameSite, secure, path, maxAge,
   * domain).
   */
  transactionCookieOptions?: TransactionCookieOptions;
  /**
   * A backing session data store. When provided, the stateful stores are built
   * (v4 `StatefulSessionStore` writer + engine `Auth0StatefulStateStore`
   * reader); otherwise the stateless pair is built.
   */
  store?: SessionDataStore;
  /**
   * Whether parallel (multi-tab) transactions are enabled. Mirrors
   * `options.enableParallelTransactions` (default `true`).
   */
  enableParallelTransactions?: boolean;
}

/**
 * The store bundle `AuthClient` requires after the storage-only cutover
 * (slices 1-4). Spread directly into `new AuthClient({ ...stores, ... })`.
 */
export interface TestStores {
  transactionStore: Auth0TransactionStore;
  transactionCookiePrefix: string;
  enableParallelTransactions: boolean;
  sessionStore: AbstractSessionStore;
  stateStore: Auth0StatelessStateStore | Auth0StatefulStateStore;
  stateIdentifier: string;
}

/**
 * Constructs the engine-backed store bundle the same way `Auth0Client` does in
 * `client.ts`, so unit tests can wire an `AuthClient` without duplicating the
 * cookie-option computation and store construction. This is a transitional test
 * aid: it exists to migrate the existing harness off the pre-cutover v4-store
 * construction, and is not part of the shipped SDK surface.
 *
 * The defaults match the production defaults (session `__session`, transaction
 * `__txn_`, `sameSite: "lax"`, `secure: false`, `path: "/"`, `maxAge: 3600`),
 * so `createTestStores({ secret })` reproduces the plain `{ secret }` store
 * construction tests used before.
 */
export function createTestStores({
  secret,
  session,
  sessionCookieOptions: sessionCookieOverrides,
  transactionCookieOptions: transactionCookieOverrides,
  store,
  enableParallelTransactions = true
}: CreateTestStoresOptions): TestStores {
  const sessionCookieOptions: SessionCookieOptions = {
    name: sessionCookieOverrides?.name ?? session?.cookie?.name ?? "__session",
    secure: sessionCookieOverrides?.secure ?? session?.cookie?.secure ?? false,
    sameSite:
      sessionCookieOverrides?.sameSite ?? session?.cookie?.sameSite ?? "lax",
    path: sessionCookieOverrides?.path ?? session?.cookie?.path ?? "/",
    transient:
      sessionCookieOverrides?.transient ?? session?.cookie?.transient ?? false,
    domain: sessionCookieOverrides?.domain ?? session?.cookie?.domain
  };

  const transactionCookieOptions: TransactionCookieOptions = {
    prefix: transactionCookieOverrides?.prefix ?? "__txn_",
    secure: transactionCookieOverrides?.secure ?? false,
    sameSite: transactionCookieOverrides?.sameSite ?? "lax",
    path: transactionCookieOverrides?.path ?? "/",
    maxAge: transactionCookieOverrides?.maxAge ?? 3600,
    domain: transactionCookieOverrides?.domain
  };

  // v4 session store: still the writer/deleter after the storage-only cutover.
  const sessionStore: AbstractSessionStore = store
    ? new StatefulSessionStore({
        ...session,
        secret,
        store,
        cookieOptions: sessionCookieOptions
      })
    : new StatelessSessionStore({
        ...session,
        secret,
        cookieOptions: sessionCookieOptions
      });

  // Two cookie handlers, matching client.ts: the session handler carries the
  // configured domain (the engine's native session write has no domain of its
  // own), while the transaction handler is a passthrough because the engine
  // transaction store stamps its own domain from `cookieOptions`.
  const sessionCookieHandler = new Auth0CookieHandler(
    sessionCookieOptions.domain
  );
  const transactionCookieHandler = new Auth0CookieHandler();

  const transactionStore = new Auth0TransactionStore(
    { secret },
    transactionCookieHandler,
    {
      transactionCookiePrefix: transactionCookieOptions.prefix,
      cookieOptions: {
        secure: transactionCookieOptions.secure,
        domain: transactionCookieOptions.domain,
        path: transactionCookieOptions.path,
        sameSite: transactionCookieOptions.sameSite,
        maxAge: transactionCookieOptions.maxAge
      }
    }
  );

  const legacyCookieOverrides: LegacyCookieOverrides = {
    domain: sessionCookieOptions.domain,
    path: sessionCookieOptions.path,
    secure: sessionCookieOptions.secure,
    sameSite: sessionCookieOptions.sameSite
  };

  const engineSessionConfig: SessionConfiguration & { secret: string } = {
    ...session,
    secret,
    cookie: sessionCookieOptions
  };

  const stateStore: Auth0StatelessStateStore | Auth0StatefulStateStore = store
    ? new Auth0StatefulStateStore(
        { ...engineSessionConfig, store },
        sessionCookieHandler,
        legacyCookieOverrides
      )
    : new Auth0StatelessStateStore(
        engineSessionConfig,
        sessionCookieHandler,
        legacyCookieOverrides
      );

  return {
    transactionStore,
    transactionCookiePrefix:
      transactionCookieOptions.prefix ?? DEFAULT_TRANSACTION_COOKIE_PREFIX,
    enableParallelTransactions,
    sessionStore,
    stateStore,
    stateIdentifier: sessionStore.sessionCookieName
  };
}
