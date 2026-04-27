/**
 * Auth0 client configured for mTLS (Mutual TLS, RFC 8705) authentication.
 *
 * Instead of a client secret, the SDK authenticates with Auth0 using a
 * client TLS certificate. This is achieved by:
 *
 *   1. Setting `useMtls: true` — tells the SDK to use TlsClientAuth() and
 *      route all token requests to Auth0's mTLS endpoint aliases.
 *
 *   2. Providing a `customFetch` backed by an undici Agent that attaches the
 *      client certificate to every outbound TLS connection.
 *
 * Auth0 validates the certificate, issues certificate-bound access tokens
 * (with `cnf.x5t#S256` claim), and the resource server can verify the binding
 * on every API call.
 *
 * Prerequisites:
 *   - mTLS must be enabled on your Auth0 tenant (Dashboard → Settings → Advanced)
 *   - Your application must use the "mTLS" token endpoint auth method
 *   - Provide PEM paths via MTLS_CLIENT_CERT_PATH / MTLS_CLIENT_KEY_PATH env vars
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 * @see https://auth0.com/docs/get-started/applications/configure-mtls
 */

import { readFileSync } from "fs";
import { Agent, fetch as undiciFetch } from "undici";
import { Auth0Client } from "@auth0/nextjs-auth0/server";

// ---------------------------------------------------------------------------
// Build the undici TLS agent that carries the client certificate.
// The paths are resolved once at module load time — keep the agent singleton.
// ---------------------------------------------------------------------------

const certPath = process.env.MTLS_CLIENT_CERT_PATH;
const keyPath = process.env.MTLS_CLIENT_KEY_PATH;
const caPath = process.env.MTLS_CA_CERT_PATH; // optional

if (!certPath || !keyPath) {
  throw new Error(
    "MTLS_CLIENT_CERT_PATH and MTLS_CLIENT_KEY_PATH environment variables must be set. " +
      "Copy .env.local.example to .env.local and configure your certificate paths."
  );
}

const tlsAgent = new Agent({
  connect: {
    cert: readFileSync(certPath),
    key: readFileSync(keyPath),
    ...(caPath ? { ca: readFileSync(caPath) } : {})
  }
});

/**
 * A fetch implementation that routes all requests through the mTLS agent,
 * attaching the client certificate to every outbound TLS handshake.
 */
function mtlsFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  // undici's fetch accepts a `dispatcher` option to override the agent.
  // We cast through `unknown` because the standard RequestInit type does not
  // include undici-specific options, and undici's Response type differs slightly
  // from the standard Response type.
  return undiciFetch(input as Parameters<typeof undiciFetch>[0], {
    ...(init as Parameters<typeof undiciFetch>[1]),
    dispatcher: tlsAgent
  }) as unknown as Promise<Response>;
}

// ---------------------------------------------------------------------------
// Auth0 client
// ---------------------------------------------------------------------------

export const auth0 = new Auth0Client({
  /**
   * Enable mTLS authentication.
   * - Uses TlsClientAuth() instead of ClientSecretPost — no secret in the request body.
   * - Sets `use_mtls_endpoint_aliases = true` so token requests go to
   *   `mtls_endpoint_aliases.token_endpoint` from the discovery document.
   */
  useMtls: true,

  /**
   * The TLS-aware fetch that carries the client certificate.
   * Required when `useMtls` is true.
   */
  customFetch: mtlsFetch,

  authorizationParameters: {
    scope: "openid profile email offline_access",
    // Uncomment and set your API audience if you need a resource API token:
    // audience: process.env.AUTH0_AUDIENCE,
  }
});
