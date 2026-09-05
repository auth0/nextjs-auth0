import { DPoPHandle, HttpRequestOptions } from "oauth4webapi";

import { RetryConfig } from "../../types/dpop.js";
import { GetAccessTokenOptions, TokenSet } from "../../types/index.js";

export type ResponseHeaders =
  | Record<string, string | null | undefined>
  | [string, string][]
  | { get(name: string): string | null | undefined };

// Custom init type for this fetcher
export type FetcherInit = {
  method?: string;
  headers?: HeadersInit;
  body?: BodyInit;
};

/**
 * Custom fetch implementation that returns a Response-like type.
 * Used for dependency injection to work well with oauth4webapi's protectedResourceRequest.
 *
 * @template TOutput - Response type that extends the standard Response interface
 * @param req - The Request object to be processed
 * @returns Promise that resolves to the custom response type
 */
export type CustomFetchImpl<TOutput extends Response> = (
  input: string | URL | globalThis.Request,
  init?: RequestInit
) => Promise<TOutput>;

/**
 * Factory function for creating access tokens with optional parameters.
 * Used internally to retrieve tokens for authenticated requests.
 *
 * @param getAccessTokenOptions - Options for token retrieval (scope, audience, refresh, etc.)
 * @returns Promise that resolves to the access token string
 */
export type AccessTokenFactory = (
  getAccessTokenOptions: GetAccessTokenOptions
) => Promise<string | TokenSet>;

// Aliased unused exports with underscore prefix to avoid lint errors in importing files
export type _CustomFetchImpl<TOutput extends Response> =
  CustomFetchImpl<TOutput>;
export type _AccessTokenFactory = AccessTokenFactory;

/**
 * Configuration properties specific to the Auth0 client for DPoP and HTTP operations.
 * Contains internal client settings used by the fetcher for authenticated requests.
 */
export type AuthClientProperties = {
  /** HTTP options factory for oauth4webapi requests */
  httpOptions: () => HttpRequestOptions<"GET" | "POST", undefined>;
  /** Allow insecure requests (development only) */
  allowInsecureRequests?: boolean;
  /** DPoP handle for proof-of-possession requests */
  dpopHandle?: DPoPHandle;
  /** Retry configuration for DPoP nonce errors */
  retryConfig?: RetryConfig;
};

/**
 * Minimal configuration options for creating a Fetcher instance.
 * These options can be provided by the consumer to customize fetcher behavior.
 *
 * @template TOutput - Response type that extends the standard Response interface
 */
export type FetcherMinimalConfig<TOutput extends Response> = {
  /** Custom access token factory function. If not provided, uses the default from hooks */
  getAccessToken?: AccessTokenFactory;
  /** Base URL for relative requests. Must be provided if using relative URLs */
  baseUrl?: string;
  /** Custom fetch implementation. Falls back to global fetch if not provided */
  fetch?: CustomFetchImpl<TOutput>;
};

/**
 * Complete configuration for the Fetcher class.
 * Combines minimal config with internal Auth0 client properties.
 *
 * @template TOutput - Response type that extends the standard Response interface
 */
export type FetcherConfig<TOutput extends Response> =
  FetcherMinimalConfig<TOutput> & AuthClientProperties;

/**
 * Hook functions provided by the Auth0 client to the Fetcher.
 * These provide access to client state and capabilities.
 */
export type FetcherHooks = {
  /** Check if DPoP is enabled for the current configuration */
  isDpopEnabled: () => boolean;
  /** Default access token factory from the Auth0 client */
  getAccessToken: AccessTokenFactory;
};

/**
 * Callback functions for handling specific scenarios during fetchWithAuth.
 * Allows customization of error handling and retry logic.
 *
 * @template TOutput - Response type that extends the standard Response interface
 */
export type FetchWithAuthCallbacks<TOutput> = {
  /**
   * Callback invoked when a DPoP nonce error occurs.
   * Should retry the request with updated DPoP nonce.
   * If not provided, DPoP nonce errors will be re-thrown.
   */
  onUseDpopNonceError?(): Promise<TOutput>;
};
