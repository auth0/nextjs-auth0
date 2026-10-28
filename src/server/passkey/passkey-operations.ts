import {
  PasskeyEnrollmentChallengeError,
  PasskeyEnrollmentVerifyError
} from "../../errors/index.js";
import type {
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyEnrollmentChallengeOptions,
  PasskeyEnrollmentChallengeResponse,
  PasskeyEnrollmentVerifyOptions,
  PasskeyEnrollmentVerifyResponse,
  PasskeyGetTokenOptions,
  PasskeyRegisterOptions,
  PasskeyRegisterResponse
} from "../../types/index.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import type { CookieContext } from "../engine/context.js";
import type { Engine, EngineSetup } from "../engine/create-engine.js";
import { withHttpTimeout } from "../engine/http-timeout.js";
import { createLoginHook } from "../session/login-hook.js";
import { readSession } from "../session/read-session.js";
import { retrieveAccessToken } from "../token/get-access-token.js";

type EngineRegisterOptions = Parameters<Engine["passkey"]["register"]>[0];
type EngineGetTokenOptions = Parameters<Engine["passkey"]["getToken"]>[0];

const MY_ACCOUNT_SCOPE = "create:me:authentication_methods";

/**
 * A signup challenge. The engine sends the request (`connection` is Auth0's `realm`); nothing is
 * saved.
 */
export async function registerPasskey(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasskeyRegisterOptions = {}
): Promise<PasskeyRegisterResponse> {
  const { connection, ...rest } = options;
  const engine = await setup.getEngine();
  return setup.errors.callEngine(
    "passkeyRegister",
    () =>
      engine.passkey.register(
        {
          ...rest,
          ...(connection && { realm: connection })
        } as EngineRegisterOptions,
        ctx
      ) as Promise<PasskeyRegisterResponse>
  );
}

/**
 * A login challenge. The engine sends the request; nothing is saved.
 */
export async function challengePasskey(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasskeyChallengeOptions = {}
): Promise<PasskeyChallengeResponse> {
  const { connection, organization } = options;
  const engine = await setup.getEngine();
  return setup.errors.callEngine(
    "passkeyChallenge",
    () =>
      engine.passkey.challenge(
        {
          ...(connection && { realm: connection }),
          ...(organization && { organization })
        },
        ctx
      ) as Promise<PasskeyChallengeResponse>
  );
}

/**
 * Exchanges the WebAuthn credential for tokens. The engine sends the grant, builds a session from
 * the new ID token and saves it; around it:
 * 1. the caller's `scope`, `audience` and `organization` go to the engine as given; without
 *    them the engine uses the login scope and the configured audience
 * 2. our `beforeSessionSaved` runs on the session the engine built
 * 3. MFA required: `MfaRequiredError`, its token sealed with the audience and scope of the call
 */
export async function getPasskeyToken(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasskeyGetTokenOptions
): Promise<void> {
  const { config } = setup;
  const { authSession, authResponse, connection, ...rest } = options;
  const dpopKeyPair = await getDpopKeyPair(config);
  const hook = createLoginHook(setup);
  try {
    const engine = await setup.getEngine();
    await engine.passkey.getToken(
      {
        ...rest,
        authSession,
        credential: authResponse,
        ...(connection && { realm: connection })
      } as EngineGetTokenOptions,
      ctx,
      dpopKeyPair ? { dpopKeyPair } : undefined,
      { beforeSessionSaved: hook.beforeSessionSaved }
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    throw await setup.errors.toSdkError(e, "passkeyGetToken", {
      audience:
        options.audience ?? config.authorizationParameters.audience ?? "",
      scope: options.scope ?? config.loginScope
    });
  }
}

/**
 * Starts enrolling a passkey for the signed-in user (MyAccount API, nextjs's code: the engine has
 * no enrollment). The authentication method ID is the last segment of the `Location` header.
 */
export async function enrollmentChallenge(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasskeyEnrollmentChallengeOptions = {}
): Promise<PasskeyEnrollmentChallengeResponse> {
  const { issuer, accessToken } = await myAccountToken(
    setup,
    ctx,
    PasskeyEnrollmentChallengeError
  );
  const body: Record<string, unknown> = { type: "passkey" };
  if (options.connection) body.connection = options.connection;
  if (options.userIdentityId) body.identity = options.userIdentityId;

  try {
    const response = await limitedFetch(setup)(
      new URL("/me/v1/authentication-methods", issuer).toString(),
      myAccountRequest(accessToken, body)
    );
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({
        error_description: "Failed to get passkey enrollment challenge"
      }));
      throw new PasskeyEnrollmentChallengeError(
        errorBody.error || "unknown_error",
        errorBody.error_description ||
          "Failed to get passkey enrollment challenge",
        errorBody.error ? errorBody : undefined
      );
    }
    const locationHeader = response.headers.get("Location") ?? "";
    const authenticationMethodId = locationHeader.split("/").pop() ?? "";
    if (!authenticationMethodId) {
      throw new PasskeyEnrollmentChallengeError(
        "unexpected_error",
        "No authentication method ID in Location header."
      );
    }
    const result = await response.json();
    return {
      authenticationMethodId,
      authSession: result.auth_session,
      authnParamsPublicKey: result.authn_params_public_key
    };
  } catch (e) {
    if (e instanceof PasskeyEnrollmentChallengeError) throw e;
    throw new PasskeyEnrollmentChallengeError(
      "unexpected_error",
      "Unexpected error during passkey enrollment challenge."
    );
  }
}

/**
 * Completes a passkey enrollment (MyAccount API, nextjs's code). Auth0's body is returned as is.
 */
export async function enrollmentVerify(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasskeyEnrollmentVerifyOptions
): Promise<PasskeyEnrollmentVerifyResponse> {
  const { issuer, accessToken } = await myAccountToken(
    setup,
    ctx,
    PasskeyEnrollmentVerifyError
  );

  try {
    const response = await limitedFetch(setup)(
      new URL(
        `/me/v1/authentication-methods/${options.authenticationMethodId}/verify`,
        issuer
      ).toString(),
      myAccountRequest(accessToken, {
        auth_session: options.authSession,
        authn_response: options.authResponse
      })
    );
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({
        error_description: "Failed to verify passkey enrollment"
      }));
      throw new PasskeyEnrollmentVerifyError(
        errorBody.error || "unknown_error",
        errorBody.error_description || "Failed to verify passkey enrollment",
        errorBody.error ? errorBody : undefined
      );
    }
    return (await response.json()) as PasskeyEnrollmentVerifyResponse;
  } catch (e) {
    if (e instanceof PasskeyEnrollmentVerifyError) throw e;
    throw new PasskeyEnrollmentVerifyError(
      "unexpected_error",
      "Unexpected error during passkey enrollment verification."
    );
  }
}

/**
 * The signed-in user's MyAccount token. No session (or one for another domain):
 * `not_authenticated`. The token comes from `retrieveAccessToken`, so the engine refreshes it when
 * needed and saves it in the session (nextjs never saved it); any token error: `token_error`.
 */
async function myAccountToken(
  setup: EngineSetup,
  ctx: CookieContext,
  ErrorClass:
    typeof PasskeyEnrollmentChallengeError | typeof PasskeyEnrollmentVerifyError
): Promise<{ issuer: string; accessToken: string }> {
  const { state, error } = await readSession(setup, ctx);
  if (error || !state) {
    throw new ErrorClass(
      "not_authenticated",
      error?.message ?? "The user does not have an active session."
    );
  }

  const issuer = `https://${await setup.currentDomain(ctx)}/`;
  const result = await retrieveAccessToken(setup, ctx, {
    audience: `${issuer}me/`,
    scope: MY_ACCOUNT_SCOPE
  });
  if (result.error) {
    throw new ErrorClass(
      "token_error",
      "Failed to retrieve MyAccount access token."
    );
  }
  return { issuer, accessToken: result.accessToken.token };
}

function myAccountRequest(
  accessToken: string,
  body: Record<string, unknown>
): RequestInit {
  return {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify(body)
  };
}

/**
 * `setup.fetch` with the app's `httpTimeout`. The My Account calls use it directly, so the engine's
 * time limit does not reach them.
 */
function limitedFetch(setup: EngineSetup): typeof fetch {
  return withHttpTimeout(setup.fetch, setup.config.options.httpTimeout);
}
