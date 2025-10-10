import {
  AuthorizationParameters,
  GetAccessTokenOptions
} from "../types/index.js";
import { getScopeForAudience } from "../utils/scope-helpers.js";

/**
 * A generic cache to manage in-flight requests to prevent duplicate requests.
 * This ensures that multiple simultaneous requests for the same resource
 * (based on a generated cache key) will share the same promise and result.
 */
export abstract class GenericRequestCache<TOptions, TResponse> {
  #cache = new Map<string, Promise<TResponse>>();

  /**
   * Executes a request, caching the promise to prevent duplicate requests.
   * @param requestHandler Function that performs the request and returns a promise.
   * @param options Options used to generate the cache key.
   * @returns A promise that resolves to the token response.
   */
  async execute(requestHandler: () => Promise<TResponse>, options: TOptions) {
    // Generate a cache key based on audience and scope
    const cacheKey = this.getTokenCacheKey(options);

    // See if we have an in-flight request for this key
    const inFlightRequest = this.#cache.get(cacheKey);

    // If we have an in-flight request for this key,
    // return the existing promise to prevent duplicate requests.
    if (inFlightRequest) {
      return inFlightRequest;
    }
    // Create and cache the promise for this request
    const requestPromise = requestHandler().finally(() => {
      // Clean up the cache when the request completes (success or failure)
      this.#cache.delete(cacheKey);
    });

    // Store the in-flight request in the cache
    this.#cache.set(cacheKey, requestPromise);

    return requestPromise;
  }

  /**
   * Generates a cache key for requests.
   * @param options Options used to generate the cache key.
   * @returns A unique cache key string
   */
  protected abstract getTokenCacheKey(options: TOptions): string;
}

export type TokenRequestCacheOptions = {
  options: GetAccessTokenOptions;
  authorizationParameters?: AuthorizationParameters;
};

export type TokenRequestCacheResponse = {
  token: string;
  expiresAt: number;
  scope?: string;
};
/**
 * A cache to manage in-flight token requests to prevent race conditions.
 * This ensures that multiple simultaneous requests for the same token
 * (based on audience and scope) will share the same promise and result.
 */
export class TokenRequestCache extends GenericRequestCache<
  TokenRequestCacheOptions,
  TokenRequestCacheResponse
> {
  /**
   * Generates a cache key for token requests based on audience and scope.
   * @param options The options containing audience and scope
   * @returns A unique cache key string
   */
  protected getTokenCacheKey({
    options,
    authorizationParameters
  }: {
    options: GetAccessTokenOptions;
    authorizationParameters?: AuthorizationParameters;
  }): string {
    const audience =
      options.audience ?? authorizationParameters?.audience ?? "";
    const scope =
      options.scope ??
      (authorizationParameters?.scope &&
        getScopeForAudience(authorizationParameters?.scope, audience)) ??
      "";
    return `${audience}:${scope}`;
  }
}
