import { SdkError } from "./sdk-error.js";

/**
 * Error codes for Poppy (Personal Agent Protocol) login failures.
 *
 * Experimental and subject to change.
 *
 * @category Errors
 */
export enum PoppyErrorCode {
  /**
   * The ID token looks like a Poppy guest login (an `anon_poppy@` subject or
   * the anonymous `sub_profile`) but is not a valid one, for example because it
   * has no Poppy `act`. The SDK refuses it rather than store an anonymous
   * subject as a user session. The message ends with `Reason: …`, which names
   * the failing check.
   */
  INVALID_GUEST = "invalid_poppy_guest",

  /**
   * A Poppy guest login cannot complete in a popup. Guests come from a browser
   * join, never a popup.
   */
  GUEST_NOT_SUPPORTED = "poppy_guest_not_supported",

  /**
   * Client-side `poppy.getContext()`: the context route answered 404, so the
   * `poppy` option is not set on the server or the route is not mounted.
   */
  NOT_ENABLED = "poppy_not_enabled",

  /**
   * Client-side `poppy.getContext()`: the context route failed, for example
   * because the session could not be read or the network request failed.
   */
  CONTEXT_UNAVAILABLE = "poppy_context_unavailable"
}

const DEFAULT_MESSAGES: Record<PoppyErrorCode, string> = {
  [PoppyErrorCode.INVALID_GUEST]:
    "The ID token looks like a Poppy guest login but is not a valid one, so it is neither a guest nor a user.",
  [PoppyErrorCode.GUEST_NOT_SUPPORTED]:
    "A Poppy guest login cannot complete in a popup.",
  [PoppyErrorCode.NOT_ENABLED]:
    "The Poppy context route is not available. Set the `poppy` option on Auth0Client.",
  [PoppyErrorCode.CONTEXT_UNAVAILABLE]: "The Poppy context could not be read."
};

/**
 * Thrown, or passed to `onCallback`, when a Personal Agent's login cannot be
 * handled, and thrown by the client-side `poppy.getContext()`. Check
 * `error.code` against {@link PoppyErrorCode}.
 *
 * Experimental and subject to change.
 *
 * @example Reading the code in `onCallback`
 * ```typescript
 * import { NextResponse } from "next/server";
 * import { PoppyErrorCode } from "@auth0/nextjs-auth0/errors";
 *
 * export const auth0 = new Auth0Client({
 *   poppy: { config: poppyConfig },
 *   onCallback: async (error, context) => {
 *     if (error?.code === PoppyErrorCode.INVALID_GUEST) {
 *       console.error("Poppy login refused:", error.message);
 *       return new NextResponse(error.message, { status: 500 });
 *     }
 *     // ...
 *   }
 * });
 * ```
 *
 * @category Errors
 */
export class PoppyError extends SdkError {
  /** The specific Poppy error code indicating the type of failure */
  public code: PoppyErrorCode;

  /**
   * Constructs a new `PoppyError` instance.
   *
   * @param code - The Poppy error code
   * @param message - A descriptive message; defaults to a message for the code
   */
  constructor(code: PoppyErrorCode, message?: string) {
    super(message ?? DEFAULT_MESSAGES[code]);
    this.code = code;
    this.name = "PoppyError";
    Object.setPrototypeOf(this, PoppyError.prototype);
  }
}
