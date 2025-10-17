import {
  allowInsecureRequests,
  customFetch,
  DPoPHandle,
  HttpRequestOptions,
  isDPoPNonceError,
  protectedResourceRequest
} from "oauth4webapi";

import { RetryConfig } from "../types/dpop.js";
import { GetAccessTokenOptions, TokenSet } from "../types/index.js";

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
  req: Request
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
  /**
   * @future This parameter is reserved for future implementation.
   * Currently not used - placeholder for upcoming multi-instance nonce persistence feature.
   */
  nonceStorageId?: string;
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

/**
 * Fetcher class for making authenticated HTTP requests with optional DPoP support.
 *
 * This class provides a high-level interface for making HTTP requests to protected resources
 * using OAuth 2.0 access tokens. It supports both standard Bearer token authentication and
 * DPoP (Demonstrating Proof-of-Possession) for enhanced security.
 *
 * Key Features:
 * - Automatic access token injection
 * - DPoP proof generation and nonce error retry
 * - Flexible URL handling (absolute and relative)
 * - Type-safe response handling
 * - Custom fetch implementation support
 *
 * @template TOutput - Response type that extends the standard Response interface
 *
 * @example
 * ```typescript
 * const fetcher = await auth0.createFetcher(req, {
 *   baseUrl: 'https://api.example.com',
 *   useDPoP: true
 * });
 *
 * const response = await fetcher.fetchWithAuth('/protected-resource', {
 *   method: 'POST',
 *   body: JSON.stringify({ data: 'example' })
 * });
 * ```
 */
export class Fetcher<TOutput extends Response> {
  protected readonly config: Omit<FetcherConfig<TOutput>, "fetch"> &
    Required<Pick<FetcherConfig<TOutput>, "fetch">>;

  protected readonly hooks: FetcherHooks;

  constructor(config: FetcherConfig<TOutput>, hooks: FetcherHooks) {
    this.hooks = hooks;

    this.config = {
      ...config,
      fetch:
        config.fetch ||
        // For easier testing and constructor compatibility with SSR.
        ((typeof window === "undefined"
          ? fetch
          : window.fetch.bind(window)) as () => Promise<any>)
    };
  }

  /**
   * Checks if a URL is absolute (includes protocol and domain).
   *
   * @param url - The URL string to test
   * @returns True if the URL is absolute, false otherwise
   *
   * @example
   * ```typescript
   * fetcher.isAbsoluteUrl('https://api.example.com/data') // true
   * fetcher.isAbsoluteUrl('/api/data') // false
   * fetcher.isAbsoluteUrl('//example.com/api') // true
   * ```
   */
  protected isAbsoluteUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Builds a complete URL from base URL and relative path.
   *
   * @param baseUrl - The base URL to resolve against (optional)
   * @param url - The URL or path to resolve
   * @returns The complete resolved URL
   * @throws TypeError if url is relative but baseUrl is not provided
   *
   * @example
   * ```typescript
   * fetcher.buildUrl('https://api.example.com', '/users')
   * // Returns: 'https://api.example.com/users'
   * ```
   */
  protected buildUrl(
    baseUrl: string | undefined,
    url: string | undefined
  ): string {
    if (url) {
      if (this.isAbsoluteUrl(url)) {
        return url;
      }

      if (baseUrl) {
        return `${baseUrl.replace(/\/?\/$/, "")}/${url.replace(/^\/+/, "")}`;
      }
    }

    throw new TypeError("`url` must be absolute or `baseUrl` non-empty.");
  }

  /**
   * Retrieves an access token for the current request.
   * Uses the configured access token factory or falls back to the hooks implementation.
   *
   * @param getAccessTokenOptions - Options for token retrieval (scope, audience, etc.)
   * @returns Promise that resolves to the access token string
   *
   * @example
   * ```typescript
   * const token = await fetcher.getAccessToken({
   *   scope: 'read:data',
   *   audience: 'https://api.example.com'
   * });
   * ```
   */
  protected getAccessToken(
    getAccessTokenOptions?: GetAccessTokenOptions
  ): Promise<string | TokenSet> {
    return this.config.getAccessToken
      ? this.config.getAccessToken(getAccessTokenOptions ?? {})
      : this.hooks.getAccessToken(getAccessTokenOptions ?? {});
  }

  protected buildBaseRequest(
    info: RequestInfo | URL,
    init: RequestInit | undefined
  ): Request {
    // Handle URL resolution before creating Request object
    let resolvedUrl: string | URL;

    if (info instanceof Request) {
      // If info is already a Request object, use its URL
      resolvedUrl = info.url;
    } else if (info instanceof URL) {
      // If info is a URL object, convert to string
      resolvedUrl = info.toString();
    } else {
      // info is a string - check if we need to resolve it with baseUrl
      if (this.config.baseUrl && !this.isAbsoluteUrl(info)) {
        // Resolve relative URL with baseUrl
        resolvedUrl = this.buildUrl(this.config.baseUrl, info);
      } else {
        // Use as-is (either absolute URL or no baseUrl configured)
        resolvedUrl = info;
      }
    }

    // Create Request object with resolved URL
    return new Request(resolvedUrl, init);
  }

  protected getHeader(headers: ResponseHeaders, name: string): string {
    if (Array.isArray(headers)) {
      return new Headers(headers).get(name) || "";
    }

    if (typeof headers.get === "function") {
      return headers.get(name) || "";
    }

    return (headers as Record<string, string | null | undefined>)[name] || "";
  }

  protected async internalFetchWithAuth(
    info: RequestInfo | URL,
    init: RequestInit | undefined,
    callbacks: FetchWithAuthCallbacks<TOutput>,
    getAccessTokenOptions?: GetAccessTokenOptions
  ): Promise<TOutput> {
    const request = this.buildBaseRequest(info, init);
    const accessTokenResponse = await this.getAccessToken(
      getAccessTokenOptions
    );

    let useDpop: boolean;
    let accessToken: string;
    if (typeof accessTokenResponse === "string") {
      useDpop = this.config.dpopHandle ? true : false;
      accessToken = accessTokenResponse;
    } else {
      useDpop = this.config.dpopHandle
        ? accessTokenResponse.token_type?.toLowerCase() === "dpop"
        : false;
      accessToken = accessTokenResponse.accessToken;
    }

    try {
      // Make (DPoP)-authenticated request using oauth4webapi
      const response = await protectedResourceRequest(
        accessToken,
        request.method,
        new URL(request.url),
        request.headers,
        request.body,
        {
          ...this.config.httpOptions(),
          [customFetch]: (url: string, options: any) => {
            const tmpRequest = new Request(url, options);
            return this.config.fetch(tmpRequest);
          },
          [allowInsecureRequests]: this.config.allowInsecureRequests || false,
          ...(useDpop && { DPoP: this.config.dpopHandle })
        }
      );

      return response as TOutput;
    } catch (error: any) {
      // Use oauth4webapi's isDPoPNonceError to detect nonce errors
      if (isDPoPNonceError(error) && callbacks.onUseDpopNonceError) {
        // Retry once with the callback
        return callbacks.onUseDpopNonceError();
      }

      // Re-throw non-DPoP nonce errors or if no callback available
      throw error;
    }
  }

  private isRequestInit(obj: any): obj is RequestInit {
    if (!obj || typeof obj !== "object") return false;

    // Check for GetAccessTokenOptions-specific properties
    // Since RequestInit and GetAccessTokenOptions have no common properties,
    // if any GetAccessTokenOptions property is present, it's GetAccessTokenOptions
    const getAccessTokenOptionsProps = ["refresh", "scope", "audience"];
    const hasGetAccessTokenOptionsProp = getAccessTokenOptionsProps.some(
      (prop) => Object.prototype.hasOwnProperty.call(obj, prop)
    );

    // If it has GetAccessTokenOptions props, it's NOT RequestInit
    // Otherwise, default to RequestInit (backwards compatibility)
    return !hasGetAccessTokenOptionsProp;
  }

  /**
   * Makes an authenticated HTTP request to a protected resource.
   *
   * This method automatically handles:
   * - Access token retrieval and injection
   * - DPoP proof generation (if enabled)
   * - DPoP nonce error retry logic
   * - URL resolution (absolute and relative)
   * - Type-safe response handling
   *
   * Supports multiple calling patterns for flexibility:
   * - `fetchWithAuth(url, requestInit)`
   * - `fetchWithAuth(url, getAccessTokenOptions)`
   * - `fetchWithAuth(url, requestInit, getAccessTokenOptions)`
   *
   * @param info - The URL or Request object to fetch
   * @param getAccessTokenOptions - Options for access token retrieval
   * @returns Promise that resolves to the response
   *
   * @example
   * ```typescript
   * const response = await fetcher.fetchWithAuth('/api/data');
   * const data = await response.json();
   * ```
   */
  // Overload 1: fetchWithAuth(info, getAccessTokenOptions)
  public fetchWithAuth(
    info: RequestInfo | URL,
    getAccessTokenOptions: GetAccessTokenOptions
  ): Promise<TOutput>;

  // Overload 2: fetchWithAuth(info, init)
  public fetchWithAuth(
    info: RequestInfo | URL,
    init: RequestInit
  ): Promise<TOutput>;

  // Overload 3: fetchWithAuth(info, init?, getAccessTokenOptions?)
  public fetchWithAuth(
    info: RequestInfo | URL,
    init?: RequestInit,
    getAccessTokenOptions?: GetAccessTokenOptions
  ): Promise<TOutput>;

  // Implementation
  public fetchWithAuth(
    info: RequestInfo | URL,
    initOrOptions?: RequestInit | GetAccessTokenOptions,
    getAccessTokenOptions?: GetAccessTokenOptions
  ): Promise<TOutput> {
    // Parameter disambiguation for 2-argument case
    let init: RequestInit | undefined;
    let accessTokenOptions: GetAccessTokenOptions | undefined;

    if (arguments.length === 2 && initOrOptions !== undefined) {
      // Determine if second argument is RequestInit or GetAccessTokenOptions
      if (this.isRequestInit(initOrOptions)) {
        init = initOrOptions as RequestInit;
        accessTokenOptions = undefined;
      } else {
        init = undefined;
        accessTokenOptions = initOrOptions as GetAccessTokenOptions;
      }
    } else {
      // 3-argument case or 1-argument case
      init = initOrOptions as RequestInit | undefined;
      accessTokenOptions = getAccessTokenOptions;
    }

    const callbacks: FetchWithAuthCallbacks<TOutput> = {
      onUseDpopNonceError: async () => {
        // Use configured retry values or defaults
        const retryConfig = this.config.retryConfig ?? {
          delay: 100,
          jitter: true
        };

        let delay = retryConfig.delay ?? 100;

        // Apply jitter if enabled
        if (retryConfig.jitter) {
          delay = delay * (0.5 + Math.random() * 0.5); // 50-100% of original delay
        }

        await new Promise((resolve) => setTimeout(resolve, delay));

        try {
          return await this.internalFetchWithAuth(
            info,
            init,
            {
              ...callbacks,
              // Retry on a `use_dpop_nonce` error, but just once.
              onUseDpopNonceError: undefined
            },
            accessTokenOptions
          );
        } catch (retryError: any) {
          // If the retry also fails, enhance the error with context
          if (isDPoPNonceError(retryError)) {
            const enhancedError = new Error(
              `DPoP nonce error persisted after retry: ${retryError.message}`
            );
            (enhancedError as any).code =
              retryError.code || "dpop_nonce_retry_failed";
            throw enhancedError;
          }
          // For non-DPoP errors, just re-throw
          throw retryError;
        }
      }
    };

    return this.internalFetchWithAuth(
      info,
      init,
      callbacks,
      accessTokenOptions
    );
  }
}
