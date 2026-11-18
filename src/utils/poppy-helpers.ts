import { NextResponse } from "next/server.js";

import {
  InvalidConfigurationError,
  InvalidRequestError,
  PoppyError,
  PoppyErrorCode
} from "../errors/index.js";
import { addCacheControlHeadersForSession } from "../server/cookies.js";
import type { AnonymousCookiePayload } from "../types/anonymous-session.js";
import type { SessionData } from "../types/index.js";
import type {
  PoppyActClaim,
  PoppyAgentState,
  PoppyContext,
  PoppyOptions
} from "../types/poppy.js";
import {
  ANONYMOUS_SUB_PROFILE,
  DEFAULT_POPPY_GUEST_SUBJECT_PREFIX,
  POPPY_REQUIRED_ACT_CLAIMS
} from "./poppy-constants.js";
import {
  buildPoppyDiscoveryDocuments,
  type PoppyDiscoveryDocuments
} from "./poppy-discovery-helpers.js";
import { isSessionCeilingReached, isUnixSeconds } from "./session-helpers.js";
import { toSafeRedirect } from "./url-helpers.js";

/** Extra ID token claims kept in `session.user` for Poppy, beyond the defaults. */
const POPPY_PROFILE_CLAIMS = ["sub_profile", "client_profile"];

/** Everything AuthClient needs for Poppy, resolved once from `PoppyOptions`. */
export interface PoppyRuntime {
  discovery: PoppyDiscoveryDocuments;
  issuer: string;
  guestSubjectPrefix: string;
}

/** An anonymous cookie that holds a Poppy guest. */
export type PoppyGuestCookie = AnonymousCookiePayload & {
  poppy: PoppyAgentState;
};

/** The result of looking at a login's ID token claims. */
export type PoppyLogin =
  | { kind: "human" }
  | { kind: "agent"; state: PoppyAgentState }
  | { kind: "guest"; state: PoppyAgentState }
  // Looks like a guest but isn't a valid one: fail closed, never a user.
  | { kind: "invalid_guest" }
  // Has a Poppy act but no valid sub or exp: fail closed, never a person.
  | { kind: "invalid_agent" };

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new InvalidConfigurationError(
      `Invalid poppy option: ${field} must be a non-empty string.`
    );
  }
  return value;
}

/**
 * Validates `PoppyOptions` and resolves the defaults. Throws
 * `InvalidConfigurationError`, so a bad option fails when the client is created.
 */
export function resolvePoppyRuntime(options: PoppyOptions): PoppyRuntime {
  const discovery = buildPoppyDiscoveryDocuments(options.config);
  return {
    discovery,
    issuer: options.config.auth.issuer,
    guestSubjectPrefix:
      options.guestSubjectPrefix === undefined
        ? DEFAULT_POPPY_GUEST_SUBJECT_PREFIX
        : requireNonEmptyString(
            options.guestSubjectPrefix,
            "guestSubjectPrefix"
          )
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasAnonymousSubProfile(claims: Record<string, unknown>): boolean {
  const value = claims.sub_profile;
  return (
    typeof value === "string" &&
    value.split(" ").includes(ANONYMOUS_SUB_PROFILE)
  );
}

/**
 * Reads the agent state from validated ID token claims, or `undefined` when the
 * login is not a Personal Agent's.
 *
 * Auth0's browser join puts the agent in `act`: `sub` (the Auth0 agent ID, or
 * the client metadata URL when no Auth0 agent is linked), `poppy_sid`,
 * `poppy_user_id`, and optionally `poppy_agent_id`, `client_id`,
 * `sub_profile` and `iss`. Requiring the two Poppy IDs, not only `act.sub`,
 * keeps an `act` that an Action sets for a person impersonating a customer
 * (`api.authentication.setActor()`) from being taken for an agent. The whole
 * `act` is kept as Auth0 sent it.
 */
export function readPoppyAgentState(
  claims: Record<string, unknown>
): PoppyAgentState | undefined {
  const { act, sub, sub_profile: subProfile } = claims;
  if (!isRecord(act) || !isPoppyAct(act) || !isNonEmptyString(sub)) {
    return undefined;
  }

  // The website's session must not outlive the join's tokens, which Auth0
  // caps at 2 hours. The tokens carry no separate Poppy Session deadline.
  if (!isUnixSeconds(claims.exp)) {
    return undefined;
  }

  return {
    sub,
    ...(typeof subProfile === "string" && { sub_profile: subProfile }),
    act: { ...act },
    sessionExpiresAt: claims.exp
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPoppyAct(act: Record<string, unknown>): act is PoppyActClaim {
  return POPPY_REQUIRED_ACT_CLAIMS.every((name) => isNonEmptyString(act[name]));
}

/**
 * Says why a login that looks like a guest is not a valid one, for an error
 * message. Mirrors the checks in {@link classifyPoppyLogin} and
 * {@link readPoppyAgentState}. It names the claims it found but never prints
 * their values, apart from `sub_profile`, which is a short label and not user
 * data.
 */
export function explainPoppyGuestFailure(
  claims: Record<string, unknown>,
  runtime: PoppyRuntime
): string {
  const sub = claims.sub;
  if (typeof sub !== "string" || !sub.startsWith(runtime.guestSubjectPrefix)) {
    return `sub_profile marks an anonymous subject, but sub does not start with "${runtime.guestSubjectPrefix}"`;
  }
  if (!hasAnonymousSubProfile(claims)) {
    const got =
      typeof claims.sub_profile === "string"
        ? `"${claims.sub_profile}"`
        : "missing";
    return `sub_profile is ${got}, expected it to include "${ANONYMOUS_SUB_PROFILE}"`;
  }
  const act = claims.act;
  if (act === undefined) {
    return `there is no "act" claim (the ID token has: ${Object.keys(claims).join(", ")})`;
  }
  if (!isRecord(act)) {
    return `"act" is ${Array.isArray(act) ? "an array" : `a ${typeof act}`}, not an object`;
  }
  const keys = `"act" has: ${Object.keys(act).join(", ") || "no claims"}`;
  for (const name of POPPY_REQUIRED_ACT_CLAIMS) {
    if (!isNonEmptyString(act[name])) {
      return `act.${name} is missing or not a string (${keys})`;
    }
  }
  return "the ID token exp is not a valid Unix time in seconds";
}

/**
 * Decides whether a login is a person, a signed-in agent or an agent guest.
 * Always a person when Poppy is off or there are no ID token claims.
 *
 * A guest has a subject starting with `anon_poppy@`, an anonymous
 * `sub_profile` and a Poppy `act`. An anonymous subject must never become a
 * user session, so a login with only some of those fails closed.
 */
export function classifyPoppyLogin(
  claims: Record<string, unknown> | undefined,
  runtime: PoppyRuntime | undefined
): PoppyLogin {
  if (!runtime || !claims) {
    return { kind: "human" };
  }
  const state = readPoppyAgentState(claims);
  const sub = claims.sub;
  const hasGuestSubject =
    typeof sub === "string" && sub.startsWith(runtime.guestSubjectPrefix);
  const isAnonymous = hasAnonymousSubProfile(claims);

  if (hasGuestSubject || isAnonymous) {
    return hasGuestSubject && isAnonymous && state
      ? { kind: "guest", state }
      : { kind: "invalid_guest" };
  }
  if (state) {
    return { kind: "agent", state };
  }
  return isRecord(claims.act) && isPoppyAct(claims.act)
    ? { kind: "invalid_agent" }
    : { kind: "human" };
}

/**
 * The error to refuse a login with, or `undefined` to let it through.
 *
 * - A login that looks like a guest but isn't a valid one fails closed, and
 *   so does one with a Poppy `act` but no valid `sub` or `exp`: an agent is
 *   never taken as a person. The reason names claims, so it is logged here
 *   and kept out of the message, which the default `onCallback` returns to
 *   the browser.
 * - A guest completes only through the redirect callback, never a popup,
 *   passkey or passwordless login: guests come from a browser join. Those
 *   logins pass `allowGuest: false`.
 * - While an agent guest is in the browser, only a signed-in agent join (any
 *   login with a Poppy agent `act`), or a new guest join (another `sub` or
 *   Poppy Session), may replace it. The agent join isn't compared with the
 *   guest: its `act.sub`, `poppy_user_id` and `poppy_sid` can differ from the
 *   guest join's, and only Auth0 issues a Poppy `act`. A person's login is
 *   refused: the browser is the agent's.
 * - The same guest coming back is refused while its access token is still
 *   valid: on Auth0 a guest's own login, or a silent one, comes back as the
 *   same guest, so redirecting would loop. Once the token has expired it is
 *   accepted as a renewal of the token, at most once per token lifetime.
 *
 * `now` is the current time in Unix seconds.
 */
export function getPoppyLoginError(
  login: PoppyLogin,
  guest: PoppyGuestCookie | undefined,
  claims: Record<string, unknown>,
  runtime: PoppyRuntime,
  options: { allowGuest?: boolean; now: number }
): PoppyError | undefined {
  if (login.kind === "invalid_guest") {
    const reason = explainPoppyGuestFailure(claims, runtime);
    console.error(`[nextjs-auth0] Refused a Poppy guest login: ${reason}.`);
    return new PoppyError(PoppyErrorCode.INVALID_GUEST, undefined, reason);
  }
  if (login.kind === "invalid_agent") {
    const reason = isNonEmptyString(claims.sub)
      ? "the ID token exp is not a valid Unix time in seconds"
      : "the ID token has no sub";
    console.error(`[nextjs-auth0] Refused a Poppy agent login: ${reason}.`);
    return new PoppyError(PoppyErrorCode.INVALID_AGENT, undefined, reason);
  }
  if (options.allowGuest === false && login.kind === "guest") {
    return new PoppyError(PoppyErrorCode.GUEST_NOT_SUPPORTED);
  }
  if (!guest || login.kind === "agent") {
    return undefined;
  }
  if (login.kind === "guest") {
    if (
      !isSamePoppyGuest(login.state, guest.poppy) ||
      guest.expires_at <= options.now
    ) {
      return undefined;
    }
  }
  return new PoppyError(PoppyErrorCode.SIGN_IN_REQUIRED);
}

/**
 * Whether two guest logins are the same guest: the same subject in the same
 * Poppy Session.
 */
export function isSamePoppyGuest(
  a: PoppyAgentState,
  b: PoppyAgentState
): boolean {
  return a.sub === b.sub && a.act.poppy_sid === b.act.poppy_sid;
}

/**
 * The 403 JSON answer for a login route whose login Poppy refused (see
 * {@link getPoppyLoginError}), or `undefined` for any other error.
 */
export function toPoppyErrorResponse(error: unknown): NextResponse | undefined {
  if (!(error instanceof PoppyError)) {
    return undefined;
  }
  const res = NextResponse.json(
    { error: error.code, error_description: error.message },
    { status: 403 }
  );
  addCacheControlHeadersForSession(res);
  return res;
}

/**
 * Recognizes Auth0's browser join, which sends the agent's browser to the
 * login route as a third-party-initiated login (OIDC Core §4) carrying `iss`
 * and `target_link_uri`.
 *
 * Removes both from `searchParams`, since neither is an /authorize parameter.
 * Without `iss`, it's a normal login and returns `undefined`. An `iss` that
 * isn't one of `issuers` throws {@link InvalidRequestError}: the login says it
 * comes from another issuer, so it is refused rather than run as a normal one
 * (OIDC Core §4). The join lands on `target_link_uri` only when it is on
 * `safeBaseUrl`'s origin; any other target is ignored with a warning, since
 * it only chooses where the browser lands. The values are not logged or
 * echoed, since anyone can put them in the URL.
 */
export function extractPoppyJoin(
  searchParams: Record<string, string>,
  issuers: string[],
  safeBaseUrl: URL
): { returnTo?: string } | undefined {
  const { iss, target_link_uri: targetLinkUri } = searchParams;
  delete searchParams.iss;
  delete searchParams.target_link_uri;

  if (iss === undefined) {
    return undefined;
  }
  if (!issuers.includes(iss)) {
    throw new InvalidRequestError(
      "Invalid iss query param: it is not the Auth0 issuer this app uses."
    );
  }
  if (targetLinkUri === undefined) {
    return {};
  }
  if (!toSafeRedirect(targetLinkUri, safeBaseUrl)) {
    console.warn(
      "[nextjs-auth0] Ignoring target_link_uri: it is not on this app's origin."
    );
    return {};
  }
  return { returnTo: targetLinkUri };
}

/**
 * Records the agent on a signed-in session and caps the session at the join
 * token's expiry. The cap reuses the IPSIE ceiling, so reads report no session
 * and refresh stops once it passes; the session stores also cap the cookie's
 * max-age at it.
 */
export function attachPoppyAgentState(
  session: SessionData,
  poppy: PoppyAgentState
): void {
  const ipsieCeiling = session.internal.sessionExpiresAt;
  session.internal = {
    ...session.internal,
    poppy,
    sessionExpiresAt:
      ipsieCeiling === undefined
        ? poppy.sessionExpiresAt
        : Math.min(ipsieCeiling, poppy.sessionExpiresAt)
  };
}

/**
 * Whether an anonymous cookie holds a Poppy guest that hasn't ended. A guest
 * lasts until its Poppy Session ends (the join's ID token `exp`), like a
 * signed-in agent. Its access token can expire earlier: the guest is still
 * there, and a silent login renews the token (see {@link getPoppyLoginError}).
 */
export function isPoppyGuestActive(
  payload: AnonymousCookiePayload
): payload is PoppyGuestCookie {
  return (
    payload.poppy !== undefined &&
    !isSessionCeilingReached(payload.poppy.sessionExpiresAt)
  );
}

/**
 * The extra user claims to keep for Poppy when no `beforeSessionSaved` hook is
 * set. `act`, which carries the Poppy IDs, is already a default claim.
 */
export function pickPoppyUserClaims(
  claims: Record<string, unknown>
): Record<string, unknown> {
  const picked: Record<string, unknown> = {};
  for (const name of POPPY_PROFILE_CLAIMS) {
    if (claims[name] !== undefined) {
      picked[name] = claims[name];
    }
  }
  return picked;
}

export const HUMAN_POPPY_CONTEXT: PoppyContext = Object.freeze({
  kind: "human"
});

/**
 * Builds the public context from stored agent state: the ID token's own `sub`
 * and `sub_profile`, and its `act` as Auth0 sent it.
 */
export function toPoppyAgentContext(
  state: PoppyAgentState,
  driving: "guest" | "signed_in",
  scope?: string
): PoppyContext {
  return {
    kind: "agent",
    state: driving,
    sub: state.sub,
    ...(state.sub_profile !== undefined && { sub_profile: state.sub_profile }),
    act: state.act,
    scopes: driving === "guest" ? [] : (scope ?? "").split(" ").filter(Boolean)
  };
}
