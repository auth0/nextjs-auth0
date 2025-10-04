export interface DpopKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export type ProtectedRequestBody = {
  url: string;
  method: string;
  headers?: Headers;
  body?: import("oauth4webapi").ProtectedResourceRequestBody;
};
