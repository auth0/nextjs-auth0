import * as oauth from "oauth4webapi"

import { DiscoveryError, SdkError } from "../errors"

export type MetadataDiscoverOptions = {
  issuer: string | URL
  httpOptions: () => oauth.HttpRequestOptions<"GET" | "POST">
  fetch: (
    input: string | URL | globalThis.Request,
    init?: any
  ) => Promise<Response>
  allowInsecureRequests: boolean
}

export type MetadataDiscoverResult =
  | [null, oauth.AuthorizationServer]
  | [SdkError, null]

export class AuthServerMetadata {
  private authorizationServerMetadata?: oauth.AuthorizationServer

  /**
   * Discover the authorization server metadata from the given issuer URL.
   *
   * @param issuer - The URL of the issuer to discover metadata from.
   * @param httpOptions - A function that returns HTTP request options for the discovery request.
   * @param fetch - A custom fetch function to perform the HTTP request.
   * @param allowInsecureRequests - A boolean indicating whether to allow insecure requests.
   * @returns A promise that resolves to a tuple containing either the discovered authorization server metadata or an error.
   *
   * @example
   * ```typescript
   * const [error, metadata] = await discover(
   *   new URL('https://example.us.auth0.com'),
   *   () => ({ method: 'GET' }),
   *   fetch,
   *   false
   * );
   * if (error) {
   *   console.error('Discovery failed:', error);
   * } else {
   *   console.log('Discovered metadata:', metadata);
   * }
   * ```
   */

  async discover({
    issuer,
    httpOptions,
    allowInsecureRequests,
    fetch,
  }: MetadataDiscoverOptions): Promise<MetadataDiscoverResult> {
    try {
      if (this.authorizationServerMetadata) {
        return [null, this.authorizationServerMetadata]
      }
      const issuerUrl = typeof issuer === "string" ? new URL(issuer) : issuer

      const authorizationServerMetadata = await oauth
        .discoveryRequest(issuerUrl, {
          ...httpOptions(),
          [oauth.customFetch]: fetch,
          [oauth.allowInsecureRequests]: allowInsecureRequests,
        })
        .then((response) => oauth.processDiscoveryResponse(issuerUrl, response))

      this.authorizationServerMetadata = authorizationServerMetadata
      return [null, authorizationServerMetadata]
    } catch (e) {
      console.error(
        `An error occurred while performing the discovery request. Please make sure the AUTH0_DOMAIN environment variable is correctly configured — the format must be 'example.us.auth0.com'. issuer=${issuer.toString()}, error:`,
        e
      )
      return [
        new DiscoveryError(
          "Discovery failed for the OpenID Connect configuration."
        ),
        null,
      ]
    }
  }
}
