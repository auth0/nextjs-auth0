import type { AnonymousSessionData, TokenSet } from "@auth0/auth0-server-js";
import { decodeJwt } from "jose";

import {
  AnonymousSessionError,
  DomainResolutionError
} from "../../errors/index.js";
import type { AnonymousSession } from "../../types/index.js";
import {
  ANONYMOUS_SUBJECT_PREFIX,
  METADATA_SIZE_LIMIT_BYTES
} from "../../utils/anonymous-session-constants.js";
import type { CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";

export interface CreateAnonymousSessionOptions {
  metadata?: Record<string, unknown>;
  audience?: string;
  scope?: string;
}

export function isAnonymousSessionEnabled({ config }: EngineSetup): boolean {
  return !!config.anonymousSession?.enabled;
}

/**
 * The stored anonymous session, or `null`. Read-only: an expired access token is returned as
 * stored, as on nextjs. A cookie the engine cannot read, or a token whose `sub` is not
 * anonymous, gives `null`; only a domain resolver failure is thrown (nextjs's request context).
 */
export async function readAnonymousSession(
  setup: EngineSetup,
  ctx: CookieContext
): Promise<AnonymousSession | null> {
  if (!isAnonymousSessionEnabled(setup)) {
    return null;
  }
  try {
    const engine = await setup.getEngine();
    const data = await engine.anonymous.getSession(ctx);
    if (!data) {
      return null;
    }
    const tokenSet = pickTokenSet(setup, data);
    return tokenSet ? toAnonymousSession(tokenSet, data.metadata) : null;
  } catch (e) {
    if (e instanceof DomainResolutionError) {
      throw e;
    }
    return null;
  }
}

/**
 * The anonymous session with a usable access token, or `null` when there is none (the GET
 * route). The engine renews the token when it has expired, and deletes the session when Auth0
 * says it is gone (`session_expired`, `invalid_session_token`), then the error is thrown.
 */
export async function fetchAnonymousSession(
  setup: EngineSetup,
  ctx: CookieContext
): Promise<AnonymousSession | null> {
  const { audience, scope } = setup.config.anonymousSession ?? {};
  const engine = await setup.getEngine();
  const found = await setup.errors.callEngine("anonymous", async () => {
    const data = await engine.anonymous.getSession(ctx);
    if (!data) {
      return undefined;
    }
    try {
      const tokenSet = await engine.anonymous.getAccessToken(
        { audience, scope },
        ctx
      );
      return { tokenSet, metadata: data.metadata };
    } catch (e) {
      // Deleted between the two calls.
      if (
        (e as { name?: unknown } | null)?.name ===
        "MissingAnonymousSessionError"
      ) {
        return undefined;
      }
      throw e;
    }
  });
  if (!found) {
    return null;
  }
  try {
    return toAnonymousSession(found.tokenSet, found.metadata);
  } catch {
    // nextjs's read path: an unusable token is no session.
    return null;
  }
}

/**
 * Creates an anonymous session; the engine sends the request and writes the cookie. nextjs's
 * checks come first, before any request: the feature is on, and the metadata is a plain object
 * of at most 1KB. Audience and scope: the call's, else the configured ones.
 */
export async function createAnonymousSession(
  setup: EngineSetup,
  ctx: CookieContext,
  options?: CreateAnonymousSessionOptions
): Promise<AnonymousSession> {
  if (!isAnonymousSessionEnabled(setup)) {
    throw new AnonymousSessionError(
      "unauthorized_client",
      "Anonymous sessions are not enabled for this client."
    );
  }
  const metadata = options?.metadata;
  if (metadata !== undefined) {
    assertMetadata(metadata);
  }

  const { audience, scope } = setup.config.anonymousSession ?? {};
  const engine = await setup.getEngine();
  const tokenSet = await setup.errors.callEngine("anonymous", () =>
    engine.anonymous.createSession(
      {
        audience: options?.audience || audience,
        scope: options?.scope || scope,
        // The engine types metadata as strings; nextjs accepts any JSON value and sends it as is.
        ...(metadata && { metadata: metadata as Record<string, string> })
      },
      ctx
    )
  );
  return toAnonymousSession(tokenSet, metadata);
}

/**
 * The token shown for the session: the one for the configured audience (the engine's default
 * when none is configured), else the first one stored.
 */
function pickTokenSet(
  { config }: EngineSetup,
  data: AnonymousSessionData
): TokenSet | undefined {
  const audience =
    config.anonymousSession?.audience ??
    config.authorizationParameters.audience;
  return (
    (audience && data.tokenSets.find((t) => t.audience === audience)) ||
    data.tokenSets[0]
  );
}

/**
 * nextjs's public session: the `id` is the access token's `sub`, which must be anonymous.
 */
function toAnonymousSession(
  tokenSet: TokenSet,
  metadata?: Record<string, unknown>
): AnonymousSession {
  let id: unknown;
  try {
    id = decodeJwt(tokenSet.accessToken).sub;
  } catch {
    throw new AnonymousSessionError(
      "invalid_session_token",
      "Failed to decode access token"
    );
  }
  if (typeof id !== "string" || !id.startsWith(ANONYMOUS_SUBJECT_PREFIX)) {
    throw new AnonymousSessionError(
      "invalid_session_token",
      "Access token sub claim is not a valid anonymous session ID"
    );
  }
  return {
    id,
    accessToken: tokenSet.accessToken,
    expiresAt: tokenSet.expiresAt,
    ...(metadata && { metadata })
  };
}

function assertMetadata(metadata: unknown): void {
  if (
    metadata === null ||
    typeof metadata !== "object" ||
    Array.isArray(metadata)
  ) {
    throw new AnonymousSessionError(
      "invalid_request",
      "Metadata must be a plain object"
    );
  }
  const size = new TextEncoder().encode(JSON.stringify(metadata)).byteLength;
  if (size > METADATA_SIZE_LIMIT_BYTES) {
    throw new AnonymousSessionError(
      "metadata_too_large",
      "Metadata exceeds 1KB limit",
      `Metadata size: ${size} bytes (max: ${METADATA_SIZE_LIMIT_BYTES})`,
      { size, limit: METADATA_SIZE_LIMIT_BYTES }
    );
  }
}
