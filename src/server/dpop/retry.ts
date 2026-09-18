import { generateKeyPair } from "oauth4webapi";

import { DpopKeyPair } from "../../types/dpop.js";

/**
 * Detects if the current environment is Edge Runtime.
 * Edge Runtime environments have limited Node.js API support.
 */
export function isEdgeRuntime(): boolean {
  return typeof (globalThis as any).EdgeRuntime === "string";
}

/**
 * Generates a new ES256 key pair for DPoP (Demonstrating Proof-of-Possession) operations.
 *
 * This function creates a cryptographically secure ES256 key pair suitable for DPoP proof
 * generation. The generated keys use the P-256 elliptic curve with SHA-256 hashing,
 * which is the required algorithm for DPoP as specified in RFC 9449.
 *
 * @returns Promise that resolves to a DpopKeyPair containing the private and public keys
 *
 * @example
 * ```typescript
 * import { generateDpopKeyPair } from "@auth0/nextjs-auth0/server";
 *
 * const keyPair = await generateDpopKeyPair();
 *
 * const auth0 = new Auth0Client({
 *   useDPoP: true,
 *   dpopKeyPair: keyPair
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
 */
export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}
