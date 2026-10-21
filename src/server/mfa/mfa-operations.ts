import type {
  AuthenticatorResponse,
  ChallengeResponse as EngineChallengeResponse,
  EnrollmentResponse as EngineEnrollmentResponse
} from "@auth0/auth0-auth-js";

import {
  MfaNoAvailableFactorsError,
  MfaVerifyError
} from "../../errors/index.js";
import type {
  EnrollOobOptions,
  EnrollOtpOptions,
  MfaVerifyResponse,
  VerifyMfaOptions
} from "../../types/index.js";
import { decryptMfaToken } from "../../utils/mfa-utils.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import type { CookieContext } from "../engine/context.js";
import type { Engine, EngineSetup } from "../engine/create-engine.js";
import { createLoginHook } from "../session/login-hook.js";
import { readSession } from "../session/read-session.js";

type EngineVerifyOptions = Parameters<Engine["mfa"]["verify"]>[0];
type EngineVerifyResult = Awaited<ReturnType<Engine["mfa"]["verify"]>>;
// One of the engine's credential forms, without the token.
type EngineCredential = EngineVerifyOptions extends infer O
  ? O extends unknown
    ? Omit<O, "mfaToken">
    : never
  : never;

/**
 * The authenticators enrolled by the user. The engine sends the request; the list is then
 * filtered by the challenge types of the `mfa_requirements` sealed in the token, as on `main`
 * (none: all are returned).
 */
export async function listAuthenticators(
  setup: EngineSetup,
  ctx: CookieContext,
  encryptedToken: string
): Promise<AuthenticatorResponse[]> {
  const context = await decryptMfaToken(encryptedToken, setup.config.secret);
  const engine = await setup.getEngine();
  const authenticators = await setup.errors.callEngine(
    "mfaGetAuthenticators",
    () =>
      engine.mfa.listAuthenticators(
        { mfaToken: context.mfaToken },
        undefined,
        ctx
      )
  );

  const allowedTypes = new Set(
    (context.mfaRequirements?.challenge ?? []).map((c) => c.type.toLowerCase())
  );
  if (allowedTypes.size === 0) {
    return authenticators;
  }
  return authenticators.filter(
    (auth) => auth.type && allowedTypes.has(auth.type.toLowerCase())
  );
}

/**
 * Starts an MFA challenge. When the token carries `mfa_requirements`, only their challenge types
 * are allowed (`main`'s check, before any request); without them, any type is.
 */
export async function challengeAuthenticator(
  setup: EngineSetup,
  ctx: CookieContext,
  encryptedToken: string,
  challengeType: string,
  authenticatorId?: string
): Promise<EngineChallengeResponse> {
  const context = await decryptMfaToken(encryptedToken, setup.config.secret);

  if (context.mfaRequirements?.challenge) {
    const allowedTypes = new Set(
      context.mfaRequirements.challenge.map((c) => c.type.toLowerCase())
    );
    if (allowedTypes.size === 0) {
      throw new MfaNoAvailableFactorsError(
        "No MFA challenge types available in mfa_requirements"
      );
    }
    if (!allowedTypes.has(challengeType.toLowerCase())) {
      throw new MfaNoAvailableFactorsError(
        `Challenge type "${challengeType}" is not allowed by mfa_requirements. Allowed: ${[...allowedTypes].join(", ")}`
      );
    }
  }

  const engine = await setup.getEngine();
  return setup.errors.callEngine("mfaChallenge", () =>
    engine.mfa.challengeAuthenticator(
      {
        mfaToken: context.mfaToken,
        challengeType:
          challengeType as EngineChallengeResponse["challengeType"],
        ...(authenticatorId && { authenticatorId })
      },
      undefined,
      ctx
    )
  );
}

/**
 * Enrolls a new authenticator. The options are already in `authenticatorTypes` form.
 */
export async function enrollAuthenticator(
  setup: EngineSetup,
  ctx: CookieContext,
  encryptedToken: string,
  options:
    Omit<EnrollOtpOptions, "mfaToken"> | Omit<EnrollOobOptions, "mfaToken">
): Promise<EngineEnrollmentResponse> {
  const context = await decryptMfaToken(encryptedToken, setup.config.secret);
  const engine = await setup.getEngine();
  return setup.errors.callEngine("mfaEnroll", () =>
    engine.mfa.enrollAuthenticator(
      { ...options, mfaToken: context.mfaToken },
      undefined,
      ctx
    )
  );
}

/**
 * Verifies an MFA code. The engine sends the grant and saves the session: on a step-up the new
 * tokens are merged into it, with no session one is started. Around it, `main`'s rules:
 * 1. the audience and scope come from the sealed token; the audience is sent to Auth0
 * 2. a credential is `otp`, `oobCode` with `bindingCode`, or `recoveryCode`; otherwise
 *    `invalid_request`
 * 3. `checkSessionDomain` (the server method): a session stored for another domain throws, before
 *    the code is spent
 * 4. our `beforeSessionSaved` runs on the session the engine built
 * 5. chained MFA: `MfaRequiredError`, its token sealed with the same audience and scope
 */
export async function verifyMfa(
  setup: EngineSetup,
  ctx: CookieContext,
  options: VerifyMfaOptions,
  { checkSessionDomain = false }: { checkSessionDomain?: boolean } = {}
): Promise<EngineVerifyResult> {
  const { mfaToken, audience, scope } = await decryptMfaToken(
    options.mfaToken,
    setup.config.secret
  );
  const credential = toEngineCredential(options);

  if (checkSessionDomain) {
    const { error } = await readSession(setup, ctx);
    if (error) {
      throw new MfaVerifyError(error.code, error.message);
    }
  }

  const dpopKeyPair = await getDpopKeyPair(setup.config);
  const hook = createLoginHook(setup);
  try {
    const engine = await setup.getEngine();
    return await engine.mfa.verify(
      {
        ...credential,
        mfaToken,
        ...(audience && { audience })
      } as EngineVerifyOptions,
      ctx,
      dpopKeyPair ? { dpopKeyPair } : undefined,
      { beforeSessionSaved: hook.beforeSessionSaved }
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    throw await setup.errors.toSdkError(e, "mfaVerify", { audience, scope });
  }
}

/**
 * `main`'s verify result: tokens stay in the session; only a new recovery code is returned.
 */
export function toVerifyResponse(
  result: EngineVerifyResult
): MfaVerifyResponse {
  return {
    success: true as const,
    ...(result.recoveryCode !== undefined && {
      recovery_code: result.recoveryCode
    })
  };
}

function toEngineCredential(options: VerifyMfaOptions): EngineCredential {
  if ("otp" in options && options.otp) {
    return { factorType: "otp", otp: options.otp };
  }
  if (
    "oobCode" in options &&
    "bindingCode" in options &&
    options.oobCode &&
    options.bindingCode
  ) {
    return {
      factorType: "oob",
      oobCode: options.oobCode,
      bindingCode: options.bindingCode
    };
  }
  if ("recoveryCode" in options && options.recoveryCode) {
    return { factorType: "recovery-code", recoveryCode: options.recoveryCode };
  }
  throw new MfaVerifyError(
    "invalid_request",
    "At least one verification credential required (otp, oobCode+bindingCode, or recoveryCode)"
  );
}
