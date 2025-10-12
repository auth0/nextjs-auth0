import { generateKeyPair } from "oauth4webapi";

import { DpopKeyPair } from "../types/dpop.js";

export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}
