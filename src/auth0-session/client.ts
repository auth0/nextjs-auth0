import { Issuer, custom, Client, EndSessionParameters, ClientAuthMethod } from 'openid-client';
import url, { UrlObject } from 'url';
import urlJoin from 'url-join';
import createDebug from './utils/debug';
import { DiscoveryError } from './utils/errors';
import { Config } from './config';
import { ParsedUrlQueryInput } from 'querystring';
import { exportJWK } from 'jose';
import { createPrivateKey } from 'crypto';

const debug = createDebug('client');

export interface ClientFactory {
  (): Promise<Client>;
}

export type Telemetry = {
  name: string;
  version: string;
};

function sortSpaceDelimitedString(str: string): string {
  return str.split(' ').sort().join(' ');
}

export default function get(config: Config, { name, version }: Telemetry): ClientFactory {
  let client: Client | null = null;

  return async (): Promise<Client> => {
    if (client) {
      return client;
    }

    custom.setHttpOptionsDefaults({
      headers: {
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
      timeout: config.httpTimeout
    });

    let issuer: Issuer<Client>;
    try {
      issuer = await Issuer.discover(config.issuerBaseURL);
    } catch (e) {
      throw new DiscoveryError(e, config.issuerBaseURL);
    }

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

    let jwks;
    if (config.clientAssertionSigningKey) {
      const privateKey = createPrivateKey({ key: config.clientAssertionSigningKey });
      const jwk = await exportJWK(privateKey);
      jwks = { keys: [jwk] };
    }

    client = new issuer.Client(
      {
        client_id: config.clientID,
        client_secret: config.clientSecret,
        id_token_signed_response_alg: config.idTokenSigningAlg,
        token_endpoint_auth_method: config.clientAuthMethod as ClientAuthMethod,
        token_endpoint_auth_signing_alg: config.clientAssertionSigningAlg
      },
      jwks
    );
    client[custom.clock_tolerance] = config.clockTolerance;

    if (config.idpLogout) {
      if (
        config.auth0Logout ||
        ((url.parse(issuer.metadata.issuer).hostname as string).match('\\.auth0\\.com$') &&
          config.auth0Logout !== false)
      ) {
        Object.defineProperty(client, 'endSessionUrl', {
          value(params: EndSessionParameters) {
            const { id_token_hint, post_logout_redirect_uri, ...extraParams } = params;
            const parsedUrl: UrlObject = url.parse(urlJoin(issuer.metadata.issuer, '/v2/logout'));
            parsedUrl.query = {
              ...extraParams,
              returnTo: post_logout_redirect_uri,
              client_id: config.clientID
            };
            Object.entries(parsedUrl.query).forEach(([key, value]) => {
              if (value === null || value === undefined) {
                delete (parsedUrl.query as ParsedUrlQueryInput)[key];
              }
            });
            return url.format(parsedUrl);
          }
        });
      } else if (!issuer.end_session_endpoint) {
        debug('the issuer does not support RP-Initiated Logout');
      }
    }

    return client;
  };
}
