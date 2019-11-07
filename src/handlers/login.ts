import base64url from 'base64url';
import { randomBytes } from 'crypto';
import { IncomingMessage, ServerResponse } from 'http';

import version from '../version';
import IAuth0Settings from '../settings';
import { setCookies } from '../utils/cookies';
import { IOidcClientFactory } from '../utils/oidc-client';

function telemetry(): string {
  const bytes = Buffer.from(
    JSON.stringify({
      name: 'nextjs-auth0',
      version
    })
  );

  return bytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export interface AuthorizationParameters {
  acr_values?: string;
  audience?: string;
  display?: string;
  login_hint?: string;
  max_age?: string;
  prompt?: string;
  scope?: string;
  state?: string;
  ui_locales?: string;
  [key: string]: unknown;
}

export interface LoginOptions {
  authParams?: AuthorizationParameters;
}

export default function loginHandler(settings: IAuth0Settings, clientProvider: IOidcClientFactory) {
  return async (req: IncomingMessage, res: ServerResponse, options: LoginOptions = {}): Promise<void> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    const { state = base64url(randomBytes(48)), ...authParams } = (options && options.authParams) || {};

    // Create the authorization url.
    const client = await clientProvider();
    const authorizationUrl = client.authorizationUrl({
      redirect_uri: settings.redirectUri,
      scope: settings.scope,
      response_type: 'code',
      audience: settings.audience,
      state,
      auth0Client: telemetry(),
      ...authParams
    });

    // Set the necessary cookies
    setCookies(req, res, [
      {
        name: 'a0:state',
        value: state,
        maxAge: 60 * 60
      }
    ]);

    // Redirect to the authorize endpoint.
    res.writeHead(302, {
      Location: authorizationUrl
    });
    res.end();
  };
}
