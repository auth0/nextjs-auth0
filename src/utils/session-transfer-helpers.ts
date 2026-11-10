import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "../errors/oauth-errors.js";

/**
 * Builds the target login URL carrying the STT (and optional `organization`) as
 * query parameters. Pure string builder — no network call, nothing persisted.
 *
 * Throws `CustomTokenExchangeError(EXCHANGE_FAILED)` if `targetLoginUrl` is not a
 * valid absolute `http`/`https` URL. `targetLoginUrl` must be a trusted, app-controlled value.
 *
 * Used by `Auth0Client.buildSessionTransferRedirect`, in both domain modes.
 */
export function buildSessionTransferRedirectUrl(
  targetLoginUrl: string,
  sessionTransferToken: string,
  opts?: { organization?: string }
): string {
  let url: URL;
  try {
    url = new URL(targetLoginUrl);
  } catch {
    throw new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
      `Invalid targetLoginUrl: "${targetLoginUrl}" is not an absolute URL. ` +
        "Pass a trusted, app-controlled absolute login URL (e.g. https://app.example.com/auth/login)."
    );
  }
  const isLocalhost =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost)) {
    throw new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
      `Invalid targetLoginUrl: "${targetLoginUrl}" must use https (or http for localhost).`
    );
  }
  url.searchParams.set("session_transfer_token", sessionTransferToken);
  if (opts?.organization) {
    url.searchParams.set("organization", opts.organization);
  }
  return url.toString();
}

/**
 * Maps a server STT failure to a typed `CustomTokenExchangeErrorCode`, keyed off the
 * machine-readable `error` code only.
 *
 * Per the SDK requirements, the SDK does NOT match against `error_description` text to
 * remap failures. Today Auth0 returns these failures with a generic `error`
 * (`invalid_request`) and the detail in `error_description`, so this returns `null` and
 * the caller surfaces the raw `error`/`error_description` as `EXCHANGE_FAILED`. These
 * named constants exist for documentation and for the day the platform returns a
 * machine-readable code (`setactor_required` / `session_transfer_disabled`), at which
 * point this mapping starts firing without any further change.
 */
export function mapSttServerError(
  errorCode: string
): CustomTokenExchangeErrorCode | null {
  const code = errorCode.toLowerCase();
  if (code === "setactor_required") {
    return CustomTokenExchangeErrorCode.SETACTOR_REQUIRED;
  }
  if (code === "session_transfer_disabled") {
    return CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED;
  }
  return null;
}
