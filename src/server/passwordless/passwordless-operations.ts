import type { NextRequest } from "next/server.js";

import type {
  PasswordlessDbChallenge,
  PasswordlessDbChallengeEmailOptions,
  PasswordlessDbChallengePhoneOptions,
  PasswordlessDbGetTokenOptions,
  PasswordlessStartOptions,
  PasswordlessVerifyOptions
} from "../../types/index.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import { mergeAuthorizationParamsIntoSearchParams } from "../../utils/authorization-params-helpers.js";
import { createRouteUrl } from "../../utils/pathUtils.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import type { CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { createLoginHook } from "../session/login-hook.js";

// The engine sets these on the magic link itself; the configured ones are dropped (D9), as on
// `main`.
const MAGIC_LINK_EXCLUDED_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method"
];

/**
 * Sends a code (email or SMS) or a magic link. The engine sends the request; for a magic link it
 * also saves a transaction, completed by the callback route (D8). The magic link carries the
 * configured authorization parameters (D9); the caller's `authParams` are not sent (PL-2).
 */
export async function startPasswordless(
  setup: EngineSetup,
  ctx: CookieContext,
  req: NextRequest | undefined,
  options: PasswordlessStartOptions
): Promise<void> {
  const { config } = setup;
  const engine = await setup.getEngine();
  const { language } = options;

  await setup.errors.callEngine("passwordlessStart", () => {
    if (options.connection === "sms") {
      return engine.startPasswordless(
        { connection: "sms", phoneNumber: options.phoneNumber, language },
        ctx
      );
    }
    if (options.send !== "link") {
      return engine.startPasswordless(
        { connection: "email", email: options.email, send: "code", language },
        ctx
      );
    }
    const appBaseUrl = resolveAppBaseUrl(config.appBaseUrl, req);
    return engine.startPasswordless(
      {
        connection: "email",
        email: options.email,
        send: "link",
        redirectUri: createRouteUrl(
          config.routes.callback,
          appBaseUrl
        ).toString(),
        authParams: Object.fromEntries(
          mergeAuthorizationParamsIntoSearchParams(
            config.authorizationParameters,
            undefined,
            MAGIC_LINK_EXCLUDED_PARAMS
          )
        ),
        language
      },
      ctx
    );
  });
}

/**
 * Exchanges an email or SMS code for tokens. The engine sends the grant with the login scope and
 * the configured audience, builds the session and saves it; our `beforeSessionSaved` runs on it.
 * MFA required: `MfaRequiredError`, its token sealed with that audience and scope.
 */
export async function verifyPasswordless(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasswordlessVerifyOptions
): Promise<void> {
  const { config } = setup;
  const hook = createLoginHook(setup);
  try {
    const engine = await setup.getEngine();
    await engine.completePasswordless(
      options.connection === "sms"
        ? {
            connection: "sms",
            phoneNumber: options.phoneNumber,
            verificationCode: options.verificationCode
          }
        : {
            connection: "email",
            email: options.email,
            verificationCode: options.verificationCode
          },
      ctx,
      // The engine sends no DPoP proof on this grant (PL-1).
      undefined,
      { beforeSessionSaved: hook.beforeSessionSaved }
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    throw await setup.errors.toSdkError(e, "passwordlessVerify", {
      audience: config.authorizationParameters.audience ?? "",
      scope: config.loginScope
    });
  }
}

/**
 * An OTP challenge for a database connection user. The engine sends the request (`phoneNumber`
 * picks the phone challenge); nothing is saved.
 */
export async function challengeDbConnection(
  setup: EngineSetup,
  ctx: CookieContext,
  options:
    PasswordlessDbChallengeEmailOptions | PasswordlessDbChallengePhoneOptions
): Promise<PasswordlessDbChallenge> {
  const engine = await setup.getEngine();
  const { authSession } = await setup.errors.callEngine(
    "passwordlessDbChallenge",
    () => engine.challengePasswordlessDbConnection(options, ctx)
  );
  return { authSession };
}

/**
 * Exchanges a database connection `authSession` and OTP for tokens. The engine sends the grant
 * with the login scope and the configured audience (D10), builds the session and saves it; our
 * `beforeSessionSaved` runs on it. MFA required: `MfaRequiredError`, sealed with the same two.
 */
export async function loginWithDbOtp(
  setup: EngineSetup,
  ctx: CookieContext,
  options: PasswordlessDbGetTokenOptions
): Promise<void> {
  const { config } = setup;
  const audience = config.authorizationParameters.audience ?? undefined;
  const dpopKeyPair = await getDpopKeyPair(config);
  const hook = createLoginHook(setup);
  try {
    const engine = await setup.getEngine();
    await engine.completePasswordlessDbConnection(
      {
        authSession: options.authSession,
        otp: options.otp,
        scope: config.loginScope,
        ...(audience && { audience })
      },
      ctx,
      dpopKeyPair ? { dpopKeyPair } : undefined,
      { beforeSessionSaved: hook.beforeSessionSaved }
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    throw await setup.errors.toSdkError(e, "passwordlessDbGetToken", {
      audience: audience ?? "",
      scope: config.loginScope
    });
  }
}
