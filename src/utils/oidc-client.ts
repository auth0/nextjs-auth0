import {
  Issuer,
  custom,
  Client
} from 'openid-client';

import IAuth0Settings from '../settings';
import OidcClientSettings from '../oidc-client-settings';

export interface IOidcClientFactory {
  (): Promise<Client>;
}

interface ClientSettings {
  timeout: number;
}

export default function getClient(settings: IAuth0Settings): IOidcClientFactory {
  let client: any = null;
  const clientSettings: OidcClientSettings = settings.oidcClient || {
    httpTimeout: 2500
  };

  return async (): Promise<Client> => {
    if (client) {
      return client;
    }

    const issuer = await Issuer.discover(`https://${settings.domain}/`);
    client = new issuer.Client({
      client_id: settings.clientId,
      client_secret: settings.clientSecret,
      redirect_uris: [settings.redirectUri],
      response_types: ['code']
    });

    if (clientSettings.httpTimeout) {
      const timeout = clientSettings.httpTimeout;
      client[custom.http_options] = function setHttpOptions(options: ClientSettings): ClientSettings {
        return {
          ...options,
          timeout
        };
      };
    }

    if (clientSettings.clockTolerance) {
      client[custom.clock_tolerance] = clientSettings.clockTolerance / 1000;
    }

    return client;
  };
}
