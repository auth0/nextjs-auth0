import {
  allowInsecureRequests,
  customFetch,
  DPoPHandle,
  HttpRequestOptions,
  isDPoPNonceError,
  protectedResourceRequest
} from "oauth4webapi";

import { GetAccessTokenOptions } from "../types/index.js";

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

// CustomFetchImpl should return a Response-like type to work well with oauth4webapi protectedResourceRequest
export type CustomFetchImpl<TOutput extends Response> = (
  req: Request
) => Promise<TOutput>;

export type AccessTokenFactory = (
  getAccessTokenOptions: GetAccessTokenOptions
) => Promise<string>;

export type AuthClientProperties = {
  httpOptions: () => HttpRequestOptions<"GET" | "POST", undefined>;
  allowInsecureRequests?: boolean;
  dpopHandle?: DPoPHandle;
};

export type FetcherMinimalConfig<TOutput extends Response> = {
  getAccessToken?: AccessTokenFactory;
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
};

export type FetcherConfig<TOutput extends Response> =
  FetcherMinimalConfig<TOutput> & AuthClientProperties;

export type FetcherHooks = {
  isDpopEnabled: () => boolean;
  getAccessToken: AccessTokenFactory;
};

export type FetchWithAuthCallbacks<TOutput> = {
  onUseDpopNonceError?(): Promise<TOutput>;
};

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

  protected getAccessToken(
    getAccessTokenOptions?: GetAccessTokenOptions
  ): Promise<string> {
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
    const accessToken = await this.getAccessToken(getAccessTokenOptions);

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
          ...(this.config.dpopHandle && { DPoP: this.config.dpopHandle })
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

    // Check for RequestInit-specific properties
    const requestInitProps = [
      "method",
      "headers",
      "body",
      "mode",
      "credentials",
      "cache",
      "redirect",
      "referrer",
      "referrerPolicy",
      "integrity",
      "keepalive",
      "signal"
    ];
    const hasRequestInitProp = requestInitProps.some((prop) =>
      obj.hasOwnProperty(prop)
    );

    // Check for GetAccessTokenOptions-specific properties
    const getAccessTokenOptionsProps = ["refresh", "scope", "audience"];
    const hasGetAccessTokenOptionsProp = getAccessTokenOptionsProps.some(
      (prop) => obj.hasOwnProperty(prop)
    );

    // If it has RequestInit props and no GetAccessTokenOptions props, it's RequestInit
    // If it has GetAccessTokenOptions props and no RequestInit props, it's GetAccessTokenOptions
    // If it has both or neither, default to RequestInit (backwards compatibility)
    if (hasRequestInitProp && !hasGetAccessTokenOptionsProp) {
      return true;
    } else if (!hasRequestInitProp && hasGetAccessTokenOptionsProp) {
      return false;
    } else {
      // Ambiguous case - default to RequestInit for backwards compatibility
      return true;
    }
  }

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

    if (arguments.length === 2) {
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
      onUseDpopNonceError: () =>
        this.internalFetchWithAuth(
          info,
          init,
          {
            ...callbacks,
            // Retry on a `use_dpop_nonce` error, but just once.
            onUseDpopNonceError: undefined
          },
          accessTokenOptions
        )
    };

    return this.internalFetchWithAuth(
      info,
      init,
      callbacks,
      accessTokenOptions
    );
  }
}
