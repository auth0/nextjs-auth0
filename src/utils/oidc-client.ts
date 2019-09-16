import { Issuer, custom } from 'openid-client';

import IAuth0Settings from '../settings';
import HttpClientSettings from '../http-settings';

export interface IOidcClientFactory {
  (): Promise<any>;
}

interface OidcClientSettings {
  timeout: number;
}

export default function getClient(settings: IAuth0Settings): IOidcClientFactory {
  let client: any = null;
  const clientSettings: HttpClientSettings = settings.httpClient || {
    timeout: 2500
  };

  return async (): Promise<any> => {
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

    client[custom.http_options] = function setHttpOptions(options: OidcClientSettings): OidcClientSettings {
      return {
        ...options,
        timeout: clientSettings.timeout
      };
    };
    return client;
  };
}
