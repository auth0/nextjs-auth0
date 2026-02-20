import { NextResponse } from "next/server.js";

import { InvalidConfigurationError } from "../errors/index.js";

/**
 * Escape HTML special characters to prevent XSS injection.
 *
 * Used for text content in the postMessage callback HTML (`<p>` status text).
 * Escapes all HTML-significant characters: `& < > " ' / \``
 *
 * **Important:** Do NOT use this for JavaScript inside `<script>` tags.
 * HTML entities (`&quot;`, `&amp;`) are not valid JavaScript and cause
 * SyntaxError, silently breaking the entire script block. For script
 * contexts, use `JSON.stringify()` with `<` escaping (`\u003c`).
 *
 * @param str - Raw string to escape
 * @returns HTML-safe string
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;")
    .replace(/`/g, "&#96;");
}

/**
 * Validate a CSP nonce value contains only base64-safe characters.
 *
 * Per the CSP specification, `nonce-source` values must be base64-encoded.
 * Throws on invalid characters to prevent HTML attribute injection
 * (e.g., a nonce containing `"` could break out of `nonce="..."` attribute)
 * and to surface misconfiguration early rather than silently corrupting the
 * nonce (which would cause CSP to block the inline script).
 *
 * Allows base64 characters plus hyphens and underscores (base64url).
 *
 * @param nonce - Developer-supplied CSP nonce from {@link Auth0ClientOptions.cspNonce}
 * @returns Validated nonce (unchanged)
 * @throws {InvalidConfigurationError} If nonce contains invalid characters
 */
export function sanitizeCspNonce(nonce: string): string {
  if (!/^[A-Za-z0-9+/=\-_]+$/.test(nonce)) {
    throw new InvalidConfigurationError(
      "cspNonce must contain only base64 characters (A-Za-z0-9+/=-_). " +
        `Received: "${nonce}"`
    );
  }
  return nonce;
}

/**
 * Returns an HTML page that posts a message to the opener window.
 * Used for popup-based auth flows (returnStrategy: "postMessage").
 *
 * The HTML page:
 * 1. Sends a postMessage to window.opener with auth result
 * 2. Auto-closes after 100ms fallback
 *
 * @param options - Message payload and optional CSP nonce
 * @returns NextResponse with HTML body and appropriate headers
 */
export function createAuthCompletePostMessageResponse(options: {
  success: boolean;
  user?: { sub: string; email?: string };
  error?: { code: string; message: string };
  nonce?: string;
}): NextResponse {
  // Build the message as a JS object literal for the <script> context.
  // JSON.stringify is NOT safe in <script> context: JSON.stringify("</script>")
  // produces the literal "</script>" which the HTML parser interprets as
  // closing the <script> tag — enabling XSS via IdP claims or OAuth errors.
  //
  // Replacing < with \u003c is safe: \u003c is a valid JS Unicode escape
  // (engines evaluate it as "<") but the HTML parser never sees a "<" char,
  // so </script> injection is impossible. Unlike escapeHtml() (which produces
  // HTML entities like &quot; that are NOT valid JS), \u003c is valid in both
  // JS string literals and JSON.
  const message = (
    options.success
      ? JSON.stringify({
          type: "auth_complete",
          success: true,
          user: options.user
        })
      : JSON.stringify({
          type: "auth_complete",
          success: false,
          error: options.error
        })
  ).replace(/</g, "\\u003c");

  const nonceAttr = options.nonce
    ? ` nonce="${sanitizeCspNonce(options.nonce)}"`
    : "";

  const statusText = options.success
    ? "Authentication completed successfully. This window will close automatically."
    : "Authentication failed. Please close this window and try again.";

  const html = `<!DOCTYPE html>
<html>
<head><title>Authentication Complete</title></head>
<body>
<p>${escapeHtml(statusText)}</p>
<script${nonceAttr}>
(function(){
  try {
    if (window.opener) {
      window.opener.postMessage(${message}, window.location.origin);
    }
  } catch(e) {}
  setTimeout(function(){ window.close(); }, 100);
})();
</script>
</body>
</html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
