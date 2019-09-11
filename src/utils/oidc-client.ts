import { Issuer } from 'openid-client';

import IAuth0Settings from '../settings';

export interface IOidcClientFactory {
  (): Promise<any>;
}

export default function getClient(settings: IAuth0Settings): IOidcClientFactory {
  let issuer: any = null;
  let client: any = null;

  return async (): Promise<any> => {
    if (!issuer) {
      issuer = await Issuer.discover(`https://${settings.domain}/`);
    }

    if (!client) {
      client = new issuer.Client({
        client_id: settings.clientId,
        client_secret: settings.clientSecret,
        redirect_uris: [settings.redirectUri],
        response_types: ['code']
      });
    }

    return client;
  };
}
