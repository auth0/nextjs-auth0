import { NextApiRequest, NextApiResponse } from 'next';
import { TokenSetParameters, TokenSet } from 'openid-client';
import { ISessionStore } from '../session/store';
import getSessionFromTokenSet from '../utils/session';

export default function setSessionHandler(sessionStore: ISessionStore) {
  return async (req: NextApiRequest, res: NextApiResponse, tokenSetParameters: TokenSetParameters): Promise<void> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    // Get the claims without any OIDC specific claim.
    const session = getSessionFromTokenSet(new TokenSet(tokenSetParameters));

    // Create the session.
    await sessionStore.save(req, res, session);
  };
}
