import type { DpopKeyPair, DpopOptions } from "../../types/dpop.js";
import { validateDpopConfiguration } from "../../utils/dpopUtils.js";
import type { EngineConfig } from "../engine/resolve-config.js";

interface DpopConfig {
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;
}

const loaded = new WeakMap<EngineConfig, Promise<DpopConfig>>();

/**
 * The DPoP key pair for engine calls (`requestOptions.dpopKeyPair`), or `undefined` when DPoP is
 * off or could not be set up (bearer is used then, with the warnings nextjs prints). Loaded on
 * first use, as on nextjs, so the key code is only loaded when DPoP is on.
 */
export async function getDpopKeyPair(
  config: EngineConfig
): Promise<DpopKeyPair | undefined> {
  return (await getDpopConfig(config)).dpopKeyPair;
}

/**
 * The key pair and nextjs's resolved DPoP options (`retry`, `clockSkew`, `clockTolerance`), from
 * the same single validation as {@link getDpopKeyPair}.
 */
export function getDpopConfig(config: EngineConfig): Promise<DpopConfig> {
  if (!config.options.useDPoP) {
    return Promise.resolve({});
  }
  let dpopConfig = loaded.get(config);
  if (!dpopConfig) {
    dpopConfig = validateDpopConfiguration(config.options);
    loaded.set(config, dpopConfig);
  }
  return dpopConfig;
}
