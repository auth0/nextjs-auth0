import type { DpopKeyPair, DpopOptions } from "../../types/dpop.js";

/**
 * Configuration options for DPoP validation.
 * This interface mirrors the relevant options from Auth0ClientOptions.
 */
export interface DpopConfigurationOptions {
  useDPoP?: boolean;
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;
}
