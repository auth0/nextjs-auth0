import { InvalidConfigurationError } from "../errors/index.js";
import type {
  PoppyAgentState,
  PoppyContext,
  PoppyOptions
} from "../types/poppy.js";
import {
  ANONYMOUS_SUB_PROFILE,
  DEFAULT_POPPY_GUEST_SUBJECT_PREFIX,
  POPPY_AGENT_ID_CLAIM,
  POPPY_SESSION_ID_CLAIM,
  POPPY_USER_ID_CLAIM
} from "../utils/poppy-constants.js";
import { isUnixSeconds } from "../utils/session-helpers.js";
import {
  buildPoppyDiscoveryDocuments,
  type PoppyDiscoveryDocuments
} from "./poppy-discovery.js";

/** Extra ID token claims kept in `session.user` for Poppy, beyond the defaults. */
const POPPY_PROFILE_CLAIMS = ["sub_profile", "client_profile"];

/** Everything AuthClient needs for Poppy, resolved once from `PoppyOptions`. */
export interface PoppyRuntime {
  discovery: PoppyDiscoveryDocuments;
  issuer: string;
  guestSubjectPrefix: string;
}

/** The result of looking at a login's ID token claims. */
export type PoppyLogin =
  | { kind: "human" }
  | { kind: "agent"; state: PoppyAgentState }
  | { kind: "guest"; state: PoppyAgentState; subject: string }
  // Looks like a guest but isn't a valid one: fail closed, never a user.
  | { kind: "invalid_guest" };

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
    issuer: options.config.issuer,
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

function readActString(
  act: Record<string, unknown>,
  name: string
): string | undefined {
  const value = act[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
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
 * Auth0's browser join puts `act: { sub, poppy_sid, poppy_user_id,
 * poppy_agent_id? }` in the tokens, where `act.sub` is the agent's client
 * metadata URL. Requiring the two Poppy IDs, not only `act.sub`, keeps an `act`
 * that an Action sets for a person impersonating a customer
 * (`api.authentication.setActor()`) from being taken for an agent.
 */
export function readPoppyAgentState(
  claims: Record<string, unknown>
): PoppyAgentState | undefined {
  const act = claims.act;
  if (!isRecord(act)) {
    return undefined;
  }
  const clientId = readActString(act, "sub");
  const poppySid = readActString(act, POPPY_SESSION_ID_CLAIM);
  const poppyUserId = readActString(act, POPPY_USER_ID_CLAIM);
  if (!clientId || !poppySid || !poppyUserId) {
    return undefined;
  }

  // The website's session must not outlive the join's tokens, which Auth0
  // caps at 2 hours. The tokens carry no separate Poppy Session deadline.
  if (!isUnixSeconds(claims.exp)) {
    return undefined;
  }

  const poppyAgentId = readActString(act, POPPY_AGENT_ID_CLAIM);
  return {
    clientId,
    poppy_sid: poppySid,
    poppy_user_id: poppyUserId,
    ...(poppyAgentId !== undefined && { poppy_agent_id: poppyAgentId }),
    sessionExpiresAt: claims.exp
  };
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
  for (const name of ["sub", POPPY_SESSION_ID_CLAIM, POPPY_USER_ID_CLAIM]) {
    if (readActString(act, name) === undefined) {
      return `act.${name} is missing or not a string (${keys})`;
    }
  }
  return "the ID token exp is not a valid Unix time in seconds";
}

/**
 * Decides whether a login is a person, a signed-in agent or an agent guest.
 *
 * A guest has a subject starting with `anon_poppy@`, an anonymous
 * `sub_profile` and a Poppy `act`. An anonymous subject must never become a
 * user session, so a login with only some of those fails closed.
 */
export function classifyPoppyLogin(
  claims: Record<string, unknown>,
  runtime: PoppyRuntime
): PoppyLogin {
  const state = readPoppyAgentState(claims);
  const sub = claims.sub;
  const hasGuestSubject =
    typeof sub === "string" && sub.startsWith(runtime.guestSubjectPrefix);
  const isAnonymous = hasAnonymousSubProfile(claims);

  if (hasGuestSubject || isAnonymous) {
    return hasGuestSubject && isAnonymous && state
      ? { kind: "guest", state, subject: sub as string }
      : { kind: "invalid_guest" };
  }
  return state ? { kind: "agent", state } : { kind: "human" };
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

/** Builds the public context from stored agent state. */
export function toPoppyAgentContext(
  state: PoppyAgentState,
  driving: "guest" | "signed_in",
  scope?: string
): PoppyContext {
  return {
    kind: "agent",
    state: driving,
    agent: { clientId: state.clientId },
    poppy_sid: state.poppy_sid,
    poppy_user_id: state.poppy_user_id,
    ...(state.poppy_agent_id !== undefined && {
      poppy_agent_id: state.poppy_agent_id
    }),
    scopes: driving === "guest" ? [] : (scope ?? "").split(" ").filter(Boolean)
  };
}
