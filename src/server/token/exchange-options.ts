import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "../../errors/index.js";

/**
 * `main`'s subject token checks (custom token exchange and session transfer), with `main`'s codes
 * and texts. They run before the engine, whose own checks give `EXCHANGE_FAILED`.
 */
export function checkSubject(options: {
  subjectToken: string;
  subjectTokenType: string;
}): CustomTokenExchangeError | null {
  if (!options.subjectToken || options.subjectToken.trim() === "") {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN,
      "The subject_token is required and cannot be empty."
    );
  }
  // 10 to 100 characters: the Auth0 Token Exchange Profile rule for `subject_token_type`.
  const type = options.subjectTokenType;
  if (type.length < 10) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at least 10 characters. Received ${type.length} characters.`
    );
  }
  if (type.length > 100) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at most 100 characters. Received ${type.length} characters.`
    );
  }
  return checkTokenTypeUri(type, "subject_token_type");
}

/**
 * `main`'s actor token checks for custom token exchange: a type with an actor token, as a URI.
 */
export function checkActor(options: {
  actorToken?: string;
  actorTokenType?: string;
}): CustomTokenExchangeError | null {
  if (options.actorToken && !options.actorTokenType) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN_TYPE,
      "The actor_token_type is required when actor_token is provided."
    );
  }
  if (options.actorToken && options.actorTokenType) {
    return checkTokenTypeUri(options.actorTokenType, "actor_token_type");
  }
  return null;
}

function checkTokenTypeUri(
  type: string,
  field: "subject_token_type" | "actor_token_type"
): CustomTokenExchangeError | null {
  let isValidUrl = false;
  try {
    new URL(type);
    isValidUrl = true;
  } catch {
    // Not a URL; a URN is checked next.
  }

  // URN format: urn:<nid>:<nss> where nid is alphanumeric (can contain hyphens)
  const isValidUrn =
    /^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$/i.test(type);

  if (!isValidUrl && !isValidUrn) {
    return new CustomTokenExchangeError(
      field === "actor_token_type"
        ? CustomTokenExchangeErrorCode.INVALID_ACTOR_TOKEN_TYPE
        : CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid ${field}: must be a valid URI (URL or URN format). Received: "${type}"`
    );
  }
  return null;
}

/**
 * `additionalParameters` as the engine's `extra`: null and undefined dropped, every other value
 * sent as `String(value)`, as on `main`. The engine skips the parameters it sets itself.
 */
export function toExtra(
  additionalParameters: Record<string, unknown> | undefined
): Record<string, string> | undefined {
  if (!additionalParameters) {
    return undefined;
  }
  const extra: Record<string, string> = {};
  for (const [key, value] of Object.entries(additionalParameters)) {
    if (value !== undefined && value !== null) {
      extra[key] = String(value);
    }
  }
  return extra;
}
