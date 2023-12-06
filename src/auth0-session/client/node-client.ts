import { Auth0Request } from '../http';
import {
  CallbackExtras,
  CallbackParamsType,
  OpenIDCallbackChecks,
  TokenEndpointResponse,
  AbstractClient,
  Telemetry
} from './abstract-client';
import {
  Client,
  ClientAuthMethod,
  custom,
  CustomHttpOptionsProvider,
  EndSessionParameters,
  errors,
  generators,
  Issuer,
  IssuerMetadata
} from 'openid-client';
import { ApplicationError, DiscoveryError, EscapedError, IdentityProviderError, UserInfoError } from '../utils/errors';
import { createPrivateKey } from 'crypto';
import { exportJWK } from 'jose';
import urlJoin from 'url-join';
import createDebug from '../utils/debug';
import { IncomingMessage } from 'http';
import { AccessTokenError, AccessTokenErrorCode } from '../../utils/errors';
import { Config } from '../config';

const debug = createDebug('client');

function sortSpaceDelimitedString(str: string): string {
  return str.split(' ').sort().join(' ');
}

export class NodeClient extends AbstractClient {
  private client?: Client;

  private async getClient(): Promise<Client> {
    if (this.client) {
      return this.client;
    }
    const {
      config,
      telemetry: { name, version }
    } = this;

    const defaultHttpOptions: CustomHttpOptionsProvider = (_url, options) => ({
      ...options,
      headers: {
        ...options.headers,
        'User-Agent': `${name}/${version}`,
        ...(config.enableTelemetry
          ? {
              'Auth0-Client': Buffer.from(
                JSON.stringify({
                  name,
                  version,
                  env: {
                    node: process.version
                  }
                })
              ).toString('base64')
            }
          : undefined)
      },
      timeout: config.httpTimeout,
      agent: config.httpAgent
    });
    const applyHttpOptionsCustom = (entity: Issuer<Client> | typeof Issuer | Client) => {
      entity[custom.http_options] = defaultHttpOptions;
    };

    applyHttpOptionsCustom(Issuer);
    let issuer: Issuer<Client>;
    try {
      issuer = await Issuer.discover(config.issuerBaseURL);
    } catch (e) {
      throw new DiscoveryError(e, config.issuerBaseURL);
    }
    applyHttpOptionsCustom(issuer);

    const issuerTokenAlgs = Array.isArray(issuer.id_token_signing_alg_values_supported)
      ? issuer.id_token_signing_alg_values_supported
      : [];
    if (!issuerTokenAlgs.includes(config.idTokenSigningAlg)) {
      debug(
        'ID token algorithm %o is not supported by the issuer. Supported ID token algorithms are: %o.',
        config.idTokenSigningAlg,
        issuerTokenAlgs
      );
    }

    const configRespType = sortSpaceDelimitedString(config.authorizationParams.response_type);
    const issuerRespTypes = Array.isArray(issuer.response_types_supported) ? issuer.response_types_supported : [];
    issuerRespTypes.map(sortSpaceDelimitedString);
    if (!issuerRespTypes.includes(configRespType)) {
      debug(
        'Response type %o is not supported by the issuer. Supported response types are: %o.',
        configRespType,
        issuerRespTypes
      );
    }

    const configRespMode = config.authorizationParams.response_mode;
    const issuerRespModes = Array.isArray(issuer.response_modes_supported) ? issuer.response_modes_supported : [];
    if (configRespMode && !issuerRespModes.includes(configRespMode)) {
      debug(
        'Response mode %o is not supported by the issuer. Supported response modes are %o.',
        configRespMode,
        issuerRespModes
      );
    }

    if (config.pushedAuthorizationRequests && !issuer.pushed_authorization_request_endpoint) {
      throw new TypeError(
        'pushed_authorization_request_endpoint must be configured on the issuer to use pushedAuthorizationRequests'
      );
    }

    let jwks;
    if (config.clientAssertionSigningKey) {
      const privateKey = createPrivateKey({ key: config.clientAssertionSigningKey as string });
      const jwk = await exportJWK(privateKey);
      jwks = { keys: [jwk] };
    }

    this.client = new issuer.Client(
      {
        client_id: config.clientID,
        client_secret: config.clientSecret,
        id_token_signed_response_alg: config.idTokenSigningAlg,
        token_endpoint_auth_method: config.clientAuthMethod as ClientAuthMethod,
        token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg
      },
      jwks
    );
    applyHttpOptionsCustom(this.client);

    this.client[custom.clock_tolerance] = config.clockTolerance;
    const issuerUrl = new URL(issuer.metadata.issuer);

    if (config.idpLogout) {
      if (
        this.config.idpLogout &&
        (this.config.auth0Logout || (issuerUrl.hostname.match('\\.auth0\\.com$') && this.config.auth0Logout !== false))
      ) {
        Object.defineProperty(this.client, 'endSessionUrl', {
          value(params: EndSessionParameters) {
            const { id_token_hint, post_logout_redirect_uri, ...extraParams } = params;
            const parsedUrl = new URL(urlJoin(issuer.metadata.issuer, '/v2/logout'));
            parsedUrl.searchParams.set('client_id', config.clientID);
            post_logout_redirect_uri && parsedUrl.searchParams.set('returnTo', post_logout_redirect_uri);
            Object.entries(extraParams).forEach(([key, value]) => {
              if (value === null || value === undefined) {
                return;
              }
              parsedUrl.searchParams.set(key, value as string);
            });
            return parsedUrl.toString();
          }
        });
      } else if (!issuer.end_session_endpoint) {
        debug('the issuer does not support RP-Initiated Logout');
      }
    }

    return this.client;
  }

  async authorizationUrl(parameters: Record<string, unknown>): Promise<string> {
    const client = await this.getClient();

    if (this.config.pushedAuthorizationRequests) {
      const { request_uri } = await client.pushedAuthorizationRequest(parameters);
      parameters = { request_uri };
    }

    return client.authorizationUrl(parameters);
  }

  async callbackParams(req: Auth0Request) {
    const client = await this.getClient();
    const obj: CallbackParamsType = client.callbackParams({
      method: req.getMethod(),
      url: req.getUrl(),
      body: await req.getBody()
    } as unknown as IncomingMessage);
    return new URLSearchParams(obj);
  }

  async callback(
    redirectUri: string,
    parameters: URLSearchParams,
    checks: OpenIDCallbackChecks,
    extras: CallbackExtras
  ): Promise<TokenEndpointResponse> {
    const params = Object.fromEntries(parameters.entries());
    const client = await this.getClient();
    try {
      return await client.callback(redirectUri, params, checks, extras);
    } catch (err) {
      if (err instanceof errors.OPError) {
        throw new IdentityProviderError(err);
      } else if (err instanceof errors.RPError) {
        throw new ApplicationError(err);
        /* c8 ignore next 3 */
      } else {
        throw new EscapedError(err.message);
      }
    }
  }

  async endSessionUrl(parameters: EndSessionParameters): Promise<string> {
    const client = await this.getClient();
    return client.endSessionUrl(parameters);
  }

  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const client = await this.getClient();
    try {
      return await client.userinfo(accessToken);
    } catch (e) {
      throw new UserInfoError(e.message);
    }
  }

  async refresh(refreshToken: string, extras: { exchangeBody: Record<string, any> }): Promise<TokenEndpointResponse> {
    const client = await this.getClient();
    try {
      return await client.refresh(refreshToken, extras);
    } catch (e) {
      throw new AccessTokenError(
        AccessTokenErrorCode.FAILED_REFRESH_GRANT,
        'The request to refresh the access token failed.',
        new IdentityProviderError(e as errors.OPError)
      );
    }
  }

  generateRandomCodeVerifier(): string {
    return generators.codeVerifier();
  }

  generateRandomNonce(): string {
    return generators.nonce();
  }

  calculateCodeChallenge(codeVerifier: string): string {
    return generators.codeChallenge(codeVerifier);
  }

  async getIssuerMetadata(): Promise<IssuerMetadata> {
    const { issuer } = await this.getClient();
    return issuer.metadata;
  }
}

export const clientGetter = (telemetry: Telemetry): ((config: Config) => Promise<NodeClient>) => {
  let client: NodeClient;
  return async (config) => {
    if (!client) {
      client = new NodeClient(config, telemetry);
    }
    return client;
  };
};
