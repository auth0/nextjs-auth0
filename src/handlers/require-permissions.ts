import { promisify } from 'util';
import { NextApiResponse, NextApiRequest } from 'next';
import jwt from 'jsonwebtoken';
import jwksClient, { CertSigningKey, RsaSigningKey } from 'jwks-rsa';
import { URL } from 'url';

import { ISessionStore } from '../session/store';
import IAuth0Settings from '../settings';

export interface IApiRoute {
  (req: NextApiRequest, res: NextApiResponse): Promise<void>;
}

export default function requirePermissions(settings: IAuth0Settings, sessionStore: ISessionStore) {
  return (
    apiRoute: IApiRoute,
    expectedScopes: string[],
    options = {
      checkAllScopes: false
    }
  ): IApiRoute => async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    if (!settings.audience) {
      throw new Error('Missing audience');
    }

    if (!Array.isArray(expectedScopes)) {
      throw new Error('Parameter expectedScopes must be an array of strings representing the scsopes of the endpoint');
    }


    const session = await sessionStore.read(req);
    if (!session || !session.user) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    if (!session.accessToken) {
      throw new Error('The access token needs to be saved in the session in order to check permissions');
    }

    const decodedToken = (jwt.decode(session.accessToken, {complete: true}) as {[key: string]: any}) || {};
    const secret = await promisify(jwksClient({
      jwksUri: `https://${settings.domain}/.well-known/jwks.json`,
    }).getSigningKey)(decodedToken.header.kid);

    const {permissions = [], scope = []} = jwt.verify(
      session.accessToken,
      (secret as CertSigningKey).publicKey || (secret as RsaSigningKey).rsaPublicKey, {
        audience: settings.audience,
        issuer: new URL(`https://${settings.domain}`).href,
        algorithms: ['RS256']
      }
    ) as { permissions?: string[], scope?: string | string[]};

    const userScopes = [...(Array.isArray(scope) ? scope : scope.split(' ')), ...permissions];

    const allowed = expectedScopes[options.checkAllScopes ? 'every' : 'some'](
      scope => userScopes.includes(scope)
    );

    if (!allowed) {
      res.setHeader('WWW-Authenticate', `Bearer scope="${expectedScopes.join(' ')}", error="Insufficient scope"`);
      res.status(403).json({
        error: 'insufficient_scope',
        description: 'Insufficient scope'
      });
      return;
    }

    await apiRoute(req, res);
  };
}
