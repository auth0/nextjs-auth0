import { toSafeRedirect } from "../../utils/url-helpers.js";

// `returnTo` is stored in the transaction cookie, so it is capped as on `main`.
const MAX_RETURN_TO_BYTES = 2048;
let clampWarned = false;

/**
 * The path to go to after login: `returnTo` when it stays on the app's origin, else the default.
 * An unsafe or oversized value silently becomes the default, as on `main`.
 */
export function resolveReturnTo(
  returnTo: string | undefined,
  safeBaseUrl: string,
  fallback: string
): string {
  if (!returnTo) {
    return fallback;
  }
  const safe = toSafeRedirect(returnTo, new URL(safeBaseUrl));
  if (!safe) {
    return fallback;
  }
  const path = safe.pathname + safe.search + safe.hash;
  if (new TextEncoder().encode(path).length <= MAX_RETURN_TO_BYTES) {
    return path;
  }
  if (!clampWarned) {
    clampWarned = true;
    console.warn(
      `[auth0] returnTo value exceeds ${MAX_RETURN_TO_BYTES} bytes; clamping to ${fallback} to keep the transaction cookie under the header size limit. Shorten the returnTo value in your application.`
    );
  }
  return fallback;
}
