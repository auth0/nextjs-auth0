import { cookies } from "next/headers.js";
import { NextResponse, type NextRequest } from "next/server.js";
import type {
  ConnectionTokenSet,
  StateData,
  TransactionData
} from "@auth0/auth0-server-js";
import * as oauth from "oauth4webapi";

import {
  ConnectAccountError,
  ConnectAccountErrorCodes,
  ConnectedAccountsError,
  ConnectedAccountsErrorCodes,
  DPoPErrorCode,
  MyAccountApiError
} from "../../errors/index.js";
import {
  RESPONSE_TYPES,
  type CompleteConnectAccountResponse,
  type ConnectAccountOptions,
  type ConnectedAccount
} from "../../types/connected-accounts.js";
import type { TokenSet } from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import { createSizeLimitedFetch } from "../../utils/fetchUtils.js";
import { createRouteUrl } from "../../utils/pathUtils.js";
import { withCallContext } from "../engine/adapters/call-context.js";
import {
  requestContext,
  type CookieContext
} from "../engine/adapters/context.js";
import {
  MAX_RESPONSE_BODY_SIZE,
  type EngineSetup
} from "../engine/create-engine.js";
import { fetcherFactory } from "../fetcher/create-fetcher.js";
import type { Fetcher } from "../fetcher/fetcher.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { retrieveAccessToken, type AccessToken } from "./access-token.js";
import { readSession } from "./session.js";
import { resolveReturnTo } from "./start-login.js";

/**
 * The My Account API token the calls below send, in nextjs's shape: `token_type` only when the
 * caller had one (nextjs's public methods pass none).
 */
export type MyAccountToken = Pick<
  TokenSet,
  "accessToken" | "expiresAt" | "scope" | "token_type" | "audience"
>;

/**
 * The connect transaction, stored next to the login ones (`__txn_{state}`), with nextjs's fields.
 * The callback finishes it itself; the engine never reads it.
 */
export interface ConnectTransaction {
  responseType: RESPONSE_TYPES.CONNECT_CODE;
  codeVerifier: string;
  state: string;
  returnTo: string;
  authSession: string;
}

export function isConnectTransaction(
  transaction: unknown
): transaction is ConnectTransaction {
  return (
    (transaction as ConnectTransaction | undefined)?.responseType ===
    RESPONSE_TYPES.CONNECT_CODE
  );
}

/**
 * The issuer of the current request's domain, as the My Account API base (`https://{domain}/`).
 */
export async function issuerOf(
  setup: EngineSetup,
  ctx: CookieContext
): Promise<string> {
  return `https://${await setup.currentDomain(ctx)}/`;
}

/**
 * A My Account API token from the session (`mintMyAccountToken`): the engine refreshes it when
 * needed (MRRT) and saves the session in `ctx`, `beforeSessionSaved` included.
 */
async function myAccountToken(
  setup: EngineSetup,
  ctx: CookieContext,
  issuer: string,
  scope: string
): Promise<{ accessToken: AccessToken; refreshed: boolean }> {
  const result = await retrieveAccessToken(setup, ctx, {
    audience: `${issuer}me/`,
    scope
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

/**
 * `connectAccount(options, req?)`: the redirect to the provider, carrying the transaction cookie
 * and, when the token was refreshed, the session. When the flow cannot start, a refreshed session
 * is written best-effort to `cookies()` before the error is thrown, as on nextjs.
 */
export async function connectAccount(
  setup: EngineSetup,
  options: ConnectAccountOptions,
  req?: NextRequest | Request
): Promise<NextResponse> {
  const { ctx, scratch, nextReq } = await requestContext(req);
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  if (!state) {
    throw new ConnectAccountError({
      code: ConnectAccountErrorCodes.MISSING_SESSION,
      message: "The user does not have an active session."
    });
  }

  const issuer = await issuerOf(setup, ctx);
  const scope = "create:me:connected_accounts";
  const { accessToken, refreshed } = await myAccountToken(
    setup,
    ctx,
    issuer,
    scope
  );
  const result = await startConnectAccount(setup, ctx, nextReq, issuer, {
    ...options,
    token: {
      accessToken: accessToken.token,
      expiresAt: accessToken.expiresAt,
      scope,
      audience: accessToken.audience
    }
  });

  if (result.error) {
    if (refreshed) {
      await writeToAmbientCookies(scratch);
    }
    throw result.error;
  }

  transferCookies(scratch, result.response);
  return result.response;
}

/**
 * nextjs's `authClient.connectAccount`: creates the connect ticket at the My Account API, stores
 * the transaction in `ctx`, and returns the redirect to the provider. The caller puts the cookies
 * written to `ctx` on the redirect.
 */
export async function startConnectAccount(
  setup: EngineSetup,
  ctx: CookieContext,
  nextReq: NextRequest | undefined,
  issuer: string,
  options: ConnectAccountOptions & { token: MyAccountToken }
): Promise<
  { response: NextResponse; error?: undefined } | { error: ConnectAccountError }
> {
  const { config } = setup;
  const appBaseUrl = resolveAppBaseUrl(config.appBaseUrl, nextReq);
  const redirectUri = createRouteUrl(
    config.routes.callback,
    appBaseUrl
  ).toString();
  const returnTo = resolveReturnTo(
    options.returnTo,
    appBaseUrl,
    config.signInReturnToPath
  );

  const codeChallengeMethod = "S256";
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  const state = oauth.generateRandomState();

  let ticket: {
    connectUri: string;
    connectParams: { ticket: string };
    authSession: string;
  };
  try {
    const fetcher = await myAccountFetcher(setup, options.token);
    const res = await fetcher.fetchWithAuth(
      new URL("/me/v1/connected-accounts/connect", issuer).toString(),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          connection: options.connection,
          redirect_uri: redirectUri,
          state,
          code_challenge: codeChallenge,
          code_challenge_method: codeChallengeMethod,
          scopes: options.scopes,
          authorization_params: options.authorizationParams
        })
      }
    );
    if (!res.ok) {
      return {
        error: await connectAccountErrorFrom(
          res,
          ConnectAccountErrorCodes.FAILED_TO_INITIATE
        )
      };
    }
    const { connect_uri, connect_params, auth_session } = await res.json();
    ticket = {
      connectUri: connect_uri,
      connectParams: connect_params,
      authSession: auth_session
    };
  } catch (e) {
    return {
      error: new ConnectAccountError({
        code: ConnectAccountErrorCodes.FAILED_TO_INITIATE,
        message: isDPoPError(e)
          ? e.message
          : "An unexpected error occurred while trying to initiate the connect account flow."
      })
    };
  }

  const transaction: ConnectTransaction = {
    responseType: RESPONSE_TYPES.CONNECT_CODE,
    codeVerifier,
    state,
    returnTo,
    authSession: ticket.authSession
  };
  // Stored under the same name as a login transaction, so the callback finds it by `state`.
  await setup.transactionStore.set(
    transactionIdentifier(setup, state),
    transaction as unknown as TransactionData,
    false,
    ctx
  );

  return {
    response: NextResponse.redirect(
      `${ticket.connectUri}?ticket=${encodeURIComponent(ticket.connectParams.ticket)}`
    )
  };
}

/**
 * nextjs's `completeConnectAccount`, for the callback: the account is created at the My Account
 * API from the `connect_code`.
 */
export async function completeConnectAccount(
  setup: EngineSetup,
  issuer: string,
  options: {
    token: MyAccountToken;
    authSession: string;
    connectCode: string;
    redirectUri: string;
    codeVerifier: string;
  }
): Promise<
  | { connectedAccount: CompleteConnectAccountResponse; error?: undefined }
  | { error: ConnectAccountError }
> {
  try {
    const fetcher = await myAccountFetcher(setup, options.token);
    const res = await fetcher.fetchWithAuth(
      new URL("/me/v1/connected-accounts/complete", issuer),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          auth_session: options.authSession,
          connect_code: options.connectCode,
          redirect_uri: options.redirectUri,
          code_verifier: options.codeVerifier
        })
      }
    );
    if (!res.ok) {
      return {
        error: await connectAccountErrorFrom(
          res,
          ConnectAccountErrorCodes.FAILED_TO_COMPLETE
        )
      };
    }
    const { id, connection, access_type, scopes, created_at, expires_at } =
      await res.json();
    return {
      connectedAccount: {
        id,
        connection,
        accessType: access_type,
        scopes,
        createdAt: created_at,
        expiresAt: expires_at
      }
    };
  } catch {
    return {
      error: new ConnectAccountError({
        code: ConnectAccountErrorCodes.FAILED_TO_COMPLETE,
        message:
          "An unexpected error occurred while trying to complete the connect account flow."
      })
    };
  }
}

/**
 * `disconnectAccount(options, req?, res?)`: every account of the connection is deleted at the My
 * Account API, then the connection's cached tokens are removed from the session, also when a
 * delete failed (the error is thrown after the save), as on nextjs.
 */
export async function disconnectAccount(
  setup: EngineSetup,
  connection: string,
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined
): Promise<void> {
  return withCallContext(req, res, async (ctx) => {
    const issuer = await requireSession(setup, ctx);
    const scope = "read:me:connected_accounts delete:me:connected_accounts";
    const { accessToken } = await myAccountToken(setup, ctx, issuer, scope);
    const token = {
      accessToken: accessToken.token,
      expiresAt: accessToken.expiresAt,
      scope,
      audience: accessToken.audience
    };

    let error: ConnectedAccountsError | undefined;
    const listed = await listAccounts(setup, issuer, token);
    if (listed.error) {
      error = listed.error;
    } else {
      const matching = listed.accounts.filter(
        (account) => account.connection === connection
      );
      if (matching.length > 0) {
        // One fetcher for every delete, so a DPoP nonce is learned once.
        const fetcher = await myAccountFetcher(setup, token);
        for (const account of matching) {
          error = await deleteAccount(fetcher, issuer, account.id);
          if (error) {
            break;
          }
        }
      }
    }

    await removeConnectionTokens(
      setup,
      ctx,
      (tokenSet) => tokenSet.connection !== connection
    );
    if (error) {
      throw error;
    }
  });
}

/**
 * `getConnectedAccounts(req?, res?)`: the user's connected accounts from the My Account API. The
 * cached tokens of connections no longer listed are removed from the session.
 */
export async function getConnectedAccounts(
  setup: EngineSetup,
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined
): Promise<ConnectedAccount[]> {
  return withCallContext(req, res, async (ctx) => {
    const issuer = await requireSession(setup, ctx);
    const scope = "read:me:connected_accounts";
    const { accessToken } = await myAccountToken(setup, ctx, issuer, scope);

    const listed = await listAccounts(setup, issuer, {
      accessToken: accessToken.token,
      expiresAt: accessToken.expiresAt,
      scope,
      audience: accessToken.audience
    });
    if (listed.error) {
      throw listed.error;
    }

    const serverConnections = new Set(
      listed.accounts.map((account) => account.connection)
    );
    await removeConnectionTokens(setup, ctx, (tokenSet) =>
      serverConnections.has(tokenSet.connection)
    );
    return listed.accounts;
  });
}

/**
 * The session check of `disconnectAccount` and `getConnectedAccounts`: none, or a session ceiling
 * reached: `ConnectedAccountsError` `missing_session`; resolver mode, stored for another domain:
 * the `SessionDomainMismatchError`. Returns the request's issuer.
 */
async function requireSession(
  setup: EngineSetup,
  ctx: CookieContext
): Promise<string> {
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  if (!state) {
    throw new ConnectedAccountsError({
      code: ConnectedAccountsErrorCodes.MISSING_SESSION,
      message: "The user does not have an active session."
    });
  }
  return issuerOf(setup, ctx);
}

/**
 * Keeps the cached connection tokens `keep` accepts, and saves the session only when one was
 * removed. The session is read again from `ctx`, so a refresh the engine just saved there (a new
 * refresh token) is kept.
 */
async function removeConnectionTokens(
  setup: EngineSetup,
  ctx: CookieContext,
  keep: (tokenSet: ConnectionTokenSet) => boolean
): Promise<void> {
  const { state } = await readSession(setup, ctx);
  const current = state?.connectionTokenSets;
  if (!state || !current?.length) {
    return;
  }
  const remaining = current.filter(keep);
  if (remaining.length === current.length) {
    return;
  }
  const { connectionTokenSets: _removed, ...rest } = state;
  await setup.sessionStore.set(
    setup.config.sessionCookie.name,
    (remaining.length
      ? { ...rest, connectionTokenSets: remaining }
      : rest) as StateData,
    false,
    ctx
  );
}

/**
 * nextjs's `listConnectedAccounts`: every page of the list, failing when the pagination does not
 * end (a repeated `next`, or more than 100 pages).
 */
async function listAccounts(
  setup: EngineSetup,
  issuer: string,
  token: MyAccountToken
): Promise<
  | { accounts: ConnectedAccount[]; error?: undefined }
  | { error: ConnectedAccountsError }
> {
  try {
    const fetcher = await myAccountFetcher(setup, token);
    const accounts: ConnectedAccount[] = [];
    let next: string | undefined;
    const seenNext = new Set<string>();
    const MAX_PAGES = 100;
    let pages = 0;

    do {
      if (++pages > MAX_PAGES || (next && seenNext.has(next))) {
        // A partial list is not safe to return: callers remove cached tokens for accounts it
        // omits.
        return {
          error: new ConnectedAccountsError({
            code: ConnectedAccountsErrorCodes.FAILED_TO_LIST,
            message: "Connected-account pagination did not terminate safely."
          })
        };
      }
      if (next) {
        seenNext.add(next);
      }
      const url = new URL("/me/v1/connected-accounts/accounts", issuer);
      if (next) {
        url.searchParams.set("next", next);
      }

      const res = await fetcher.fetchWithAuth(url.toString(), {
        method: "GET",
        headers: { "Content-Type": "application/json" }
      });
      if (!res.ok) {
        return {
          error: await connectedAccountsErrorFrom(
            res,
            ConnectedAccountsErrorCodes.FAILED_TO_LIST
          )
        };
      }

      const body = await res.json();
      for (const account of body.accounts ?? []) {
        accounts.push({
          id: account.id,
          connection: account.connection,
          accessType: account.access_type,
          scopes: account.scopes,
          createdAt: account.created_at,
          expiresAt: account.expires_at,
          orgId: account.org_id
        });
      }
      next = body.next;
    } while (next);

    return { accounts };
  } catch (e) {
    return {
      error: new ConnectedAccountsError({
        code: ConnectedAccountsErrorCodes.FAILED_TO_LIST,
        message: isDPoPError(e)
          ? e.message
          : "An unexpected error occurred while trying to list the connected accounts."
      })
    };
  }
}

/**
 * nextjs's `deleteConnectedAccount`: one account, by id.
 */
async function deleteAccount(
  fetcher: Fetcher<Response>,
  issuer: string,
  id: string
): Promise<ConnectedAccountsError | undefined> {
  try {
    const url = new URL(
      `/me/v1/connected-accounts/accounts/${encodeURIComponent(id)}`,
      issuer
    );
    const res = await fetcher.fetchWithAuth(url.toString(), {
      method: "DELETE",
      headers: { "Content-Type": "application/json" }
    });
    if (!res.ok) {
      return connectedAccountsErrorFrom(
        res,
        ConnectedAccountsErrorCodes.FAILED_TO_DELETE
      );
    }
    return undefined;
  } catch (e) {
    return new ConnectedAccountsError({
      code: ConnectedAccountsErrorCodes.FAILED_TO_DELETE,
      message: isDPoPError(e)
        ? e.message
        : "An unexpected error occurred while trying to delete the connected account."
    });
  }
}

/**
 * nextjs's fetcher for the My Account API calls: its `fetch` (the app's `customFetch`, 1 MB
 * response limit) and DPoP when configured, with the token given.
 */
function myAccountFetcher(
  setup: EngineSetup,
  token: MyAccountToken
): Promise<Fetcher<Response>> {
  const { options } = setup.config;
  return fetcherFactory(setup, {
    useDPoP: options.useDPoP ?? false,
    fetch: createSizeLimitedFetch(
      options.customFetch ?? fetch,
      MAX_RESPONSE_BODY_SIZE
    ),
    getAccessToken: async () => ({
      accessToken: token.accessToken,
      expiresAt: token.expiresAt || 0,
      scope: token.scope,
      token_type: token.token_type
    })
  });
}

async function connectAccountErrorFrom(
  res: Response,
  code: ConnectAccountErrorCodes
): Promise<ConnectAccountError> {
  const verb =
    code === ConnectAccountErrorCodes.FAILED_TO_INITIATE
      ? "initiate"
      : "complete";
  const message = `The request to ${verb} the connect account flow failed with status ${res.status}.`;
  try {
    const cause = myAccountApiErrorFrom(res, await res.json());
    return new ConnectAccountError({ code, message, cause });
  } catch {
    return new ConnectAccountError({ code, message });
  }
}

async function connectedAccountsErrorFrom(
  res: Response,
  code: ConnectedAccountsErrorCodes
): Promise<ConnectedAccountsError> {
  const verb =
    code === ConnectedAccountsErrorCodes.FAILED_TO_LIST
      ? "list the connected accounts"
      : "delete the connected account";
  const message = `The request to ${verb} failed with status ${res.status}.`;
  try {
    const cause = myAccountApiErrorFrom(res, await res.json());
    return new ConnectedAccountsError({ code, message, cause });
  } catch {
    return new ConnectedAccountsError({ code, message });
  }
}

function myAccountApiErrorFrom(
  res: Response,
  body: {
    type: string;
    title: string;
    detail: string;
    validation_errors?: MyAccountApiError["validationErrors"];
  }
): MyAccountApiError {
  return new MyAccountApiError({
    type: body.type,
    title: body.title,
    detail: body.detail,
    status: res.status,
    validationErrors: body.validation_errors
  });
}

/**
 * A DPoP failure, matched on its code as nextjs does (`instanceof` breaks across copies of the
 * class).
 */
function isDPoPError(
  e: unknown
): e is { code: DPoPErrorCode; message: string } {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    "message" in e &&
    typeof (e as { message: unknown }).message === "string" &&
    Object.values(DPoPErrorCode).includes((e as { code: DPoPErrorCode }).code)
  );
}

/**
 * The transaction cookie name for a `state`: `__txn_{state}`, or `__txn_` with parallel
 * transactions off, as the login uses.
 */
export function transactionIdentifier(
  { config }: EngineSetup,
  state?: string | null
): string {
  const prefix = config.transactionCookie.prefix;
  return config.enableParallelTransactions && state
    ? `${prefix}${state}`
    : prefix;
}

/**
 * nextjs's `saveToSession(session)` with no request: the cookies written to `scratch` go to
 * `cookies()`; a write Next refuses (middleware, a Server Component) is skipped.
 */
async function writeToAmbientCookies(scratch: NextResponse): Promise<void> {
  try {
    const jar = await cookies();
    for (const cookie of scratch.cookies.getAll()) {
      jar.set(cookie);
    }
  } catch {
    if (process.env.NODE_ENV === "development") {
      console.warn(
        "Failed to persist the updated token set. `getAccessToken()` was likely called from a Server Component which cannot set cookies."
      );
    }
  }
}
