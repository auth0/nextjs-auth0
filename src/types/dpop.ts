export interface DpopKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * Configuration options for DPoP (Demonstrating Proof-of-Possession) timing validation.
 * These options configure how oauth4webapi validates DPoP proof timing.
 */
export interface DpopOptions {
  /**
   * Clock skew adjustment in seconds. Use to adjust the assumed current time.
   * Positive values if local clock is behind, negative if ahead.
   * Maps to oauth4webapi's clockSkew symbol.
   *
   * @default 0
   */
  clockSkew?: number;

  /**
   * Clock tolerance in seconds for DateTime JWT claims validation.
   * Allows for clock differences between client and server.
   * Maps to oauth4webapi's clockTolerance symbol.
   *
   * @default 30
   */
  clockTolerance?: number;
}

export type ProtectedRequestBody = {
  url: string;
  method: string;
  headers?: Headers;
  body?: import("oauth4webapi").ProtectedResourceRequestBody;
};
