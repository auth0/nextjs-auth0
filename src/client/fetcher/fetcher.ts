import { ProtectedRequestBody } from "../../types/dpop.js";

export type ResponseHeaders =
  | Record<string, string | null | undefined>
  | [string, string][]
  | { get(name: string): string | null | undefined };

export type CustomFetchMinimalOutput = {
  status: number;
  headers: ResponseHeaders;
};

export type CustomFetchImpl<TOutput extends CustomFetchMinimalOutput> = (
  info: RequestInfo | URL,
  init?: RequestInit
) => Promise<TOutput>;

export type FetcherConfig<TOutput extends CustomFetchMinimalOutput> = {
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
};

export class Fetcher<TOutput extends CustomFetchMinimalOutput> {
  protected readonly config: Omit<FetcherConfig<TOutput>, "fetch"> & {
    fetch?: CustomFetchImpl<TOutput>;
  };

  constructor(config: FetcherConfig<TOutput>) {
    this.config = {
      ...config,
      fetch: config.fetch
    };
  }

  protected getFetch(): CustomFetchImpl<TOutput> {
    if (this.config.fetch) {
      return this.config.fetch;
    }

    // Return a fetch function that resolves dynamically
    return async (
      info: RequestInfo | URL,
      init?: RequestInit
    ): Promise<TOutput> => {
      const fetchFn = typeof window !== "undefined" ? window.fetch : fetch;
      return fetchFn(info, init) as unknown as Promise<TOutput>;
    };
  }

  protected isAbsoluteUrl(url: string): boolean {
    // `http://example.com`, `https://example.com` or `//example.com`
    return /^(https?:)?\/\//i.test(url);
  }

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

  protected buildProtectedRequest(
    info: RequestInfo | URL,
    init: RequestInit | undefined,
    sessionData?: any
  ): { url: string; options: RequestInit } {
    // First, determine the final URL and method
    let finalUrl: string;
    let method = "GET";
    let headers: HeadersInit = {};
    let body: BodyInit | null = null;

    // Handle URL construction
    if (typeof info === "string") {
      finalUrl = this.isAbsoluteUrl(info)
        ? info
        : this.buildUrl(this.config.baseUrl, info);
    } else if (info instanceof URL) {
      finalUrl = info.toString();
    } else {
      // info is a Request object
      finalUrl = this.isAbsoluteUrl(info.url)
        ? info.url
        : this.buildUrl(this.config.baseUrl, info.url);
      method = info.method;
      headers = info.headers;
      body = info.body;
    }

    // Override with init values if provided
    if (init) {
      if (init.method) method = init.method;
      if (init.headers) headers = init.headers;
      if (init.body !== undefined) body = init.body;
    }

    const proxiedBody = {
      url: finalUrl,
      method: method,
      headers: headers,
      body: body,
      ...(sessionData && { sessionData })
    } as ProtectedRequestBody & { sessionData?: any };

    const protectedRequestPath =
      process.env.NEXT_PUBLIC_PROTECTED_REQUEST_ROUTE ||
      "/auth/protected-request";

    // Build the full URL for the protected request using baseUrl if available
    const protectedRequestUrl = this.config.baseUrl
      ? this.buildUrl(this.config.baseUrl, protectedRequestPath)
      : protectedRequestPath;

    // Return the URL and options for the protected request
    return {
      url: protectedRequestUrl,
      options: {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
          // "X-Timestamp": Date.now().toString()
        },
        body: JSON.stringify(proxiedBody)
      }
    };
  }

  protected async internalFetchWithAuth(
    info: RequestInfo | URL,
    init: RequestInit | undefined,
    sessionData?: any
  ): Promise<TOutput> {
    // encapsulate original request in protectedRequest
    const { url, options } = this.buildProtectedRequest(
      info,
      init,
      sessionData
    );

    // send to next server
    const fetchFn = this.getFetch();
    const response = await fetchFn(url, options);

    return response;
  }

  public fetchWithAuth(
    info: RequestInfo | URL,
    init?: RequestInit
  ): Promise<TOutput> {
    // Validate URL early for synchronous error throwing
    if (
      typeof info === "string" &&
      !this.isAbsoluteUrl(info) &&
      !this.config.baseUrl
    ) {
      throw new TypeError("`url` must be absolute or `baseUrl` non-empty.");
    }
    if (
      info instanceof Request &&
      !this.isAbsoluteUrl(info.url) &&
      !this.config.baseUrl
    ) {
      throw new TypeError("`url` must be absolute or `baseUrl` non-empty.");
    }

    return this.internalFetchWithAuth(info, init);
  }
}

/**
 * Create a new fetcher instance with custom configuration.
 *
 * @param config Optional configuration for the fetcher
 * @returns A new Fetcher instance
 *
 * @example
 * ```typescript
 * import { createFetcher } from '@auth0/nextjs-auth0/client';
 *
 * const fetcher = createFetcher({
 *   baseUrl: 'https://api.example.com'
 * });
 *
 * const response = await fetcher.fetchWithAuth('/protected-endpoint');
 * ```
 */
export function createFetcher<
  TOutput extends CustomFetchMinimalOutput = Response
>(config: FetcherConfig<TOutput> = {}): Fetcher<TOutput> {
  return new Fetcher<TOutput>(config);
}

/**
 * Default fetcher instance for convenient access to DPoP-protected resources.
 *
 * @example
 * ```typescript
 * import { fetchWithAuth } from '@auth0/nextjs-auth0/client';
 *
 * const response = await fetchWithAuth('https://api.example.com/protected-endpoint');
 * const data = await response.json();
 * ```
 */
const defaultFetcher = new Fetcher<Response>({});

/**
 * Convenience function to make DPoP/bearer protected requests using the default fetcher.
 * This function provides a native fetch()-like API while automatically handling
 * DPoP/bearer authentication through the Auth0 NextJS SDK.
 *
 * @param info The URL or Request object for the request
 * @param init Optional request initialization options
 * @returns Promise resolving to the response
 *
 * @example
 * ```typescript
 * import { fetchWithAuth } from '@auth0/nextjs-auth0/client';
 *
 * // Simple GET request
 * const response = await fetchWithAuth('https://api.example.com/data');
 * const data = await response.json();
 *
 * // POST request with body
 * const response = await fetchWithAuth('https://api.example.com/create', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({ name: 'test' })
 * });
 * ```
 */
export function fetchWithAuth(
  info: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  return defaultFetcher.fetchWithAuth(info, init);
}
