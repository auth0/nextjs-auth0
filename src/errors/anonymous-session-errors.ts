import { SdkError } from "./sdk-error.js";

/**
 * Error class for anonymous session operations.
 * Maps authorization server error codes to SDK errors; distinguishes recoverable
 * (silent recovery) from non-recoverable (throw to caller).
 */
export class AnonymousSessionError extends SdkError {
  public code: string;
  public description?: string;
  public cause?: unknown;

  /**
   * Construct an AnonymousSessionError.
   * @param code Error code from auth server or SDK validation (e.g., "metadata_too_large")
   * @param message Human-readable error message; defaults to generic message
   * @param description Server's error_description field (optional)
   * @param cause Raw error body or underlying cause (optional)
   */
  constructor(
    code: string,
    message?: string,
    description?: string,
    cause?: unknown
  ) {
    super(
      message ??
        "An error occurred while performing the anonymous session operation."
    );
    this.name = "AnonymousSessionError";
    this.code = code;
    this.description = description;
    this.cause = cause;
  }
}

/**
 * Map authorization server error response to AnonymousSessionError.
 * Populates description and cause fields from server response (CASCADE §D).
 * Codes per DESIGN §3.C7.
 *
 * @param code Error code from the authorization server or SDK validation.
 * @param serverDescription Optional `error_description` reported by the authorization
 * server. When present it is preferred over the canned message, because the
 * server description names the concrete cause (which audience was rejected,
 * which scope was refused) while the canned message only restates the code.
 * @param rawBody Raw error body or underlying cause (optional)
 */
export function mapAnonymousErrorCode(
  code: string,
  serverDescription?: string,
  rawBody?: unknown
): AnonymousSessionError {
  const codeToMessage: Record<string, string> = {
    metadata_too_large: "The metadata object exceeds the 1KB limit.",
    invalid_session_token: "The session token is invalid or malformed.",
    invalid_target:
      "The audience is unresolved or the resource server does not allow anonymous access.",
    invalid_scope: "The requested scope is not granted to anonymous subjects.",
    invalid_client: "Client authentication failed.",
    feature_not_enabled: "Anonymous sessions are not enabled on this tenant.",
    unauthorized_client: "This client is not enabled for anonymous sessions.",
    server_error: "The authorization server encountered an error.",
    invalid_request: "The request is malformed.",
    session_expired: "The session has expired."
  };

  const trimmedDescription = serverDescription?.trim();

  return new AnonymousSessionError(
    code,
    trimmedDescription || codeToMessage[code] || `An error occurred: ${code}`,
    trimmedDescription,
    rawBody
  );
}

/**
 * Map an anonymous-session error code to its HTTP status per DESIGN §3.C7.
 * 401 invalid_client; 403 feature_not_enabled / unauthorized_client;
 * 500 server_error; 400 for every other (client/request) code.
 */
export function getStatusForAnonymousError(code: string): number {
  switch (code) {
    case "invalid_client":
      return 401;
    case "feature_not_enabled":
    case "unauthorized_client":
      return 403;
    case "server_error":
      return 500;
    default:
      return 400;
  }
}
