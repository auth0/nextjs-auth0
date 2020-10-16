import { NextApiRequest, NextApiResponse } from 'next';
import IAuth0Settings from '../settings';
import isSafeRedirect from '../utils/url-helpers';
import { ResponseContext } from 'auth0-session';

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
  getState?: (req: NextApiRequest) => Record<string, any>;
  authParams?: AuthorizationParameters;
  redirectTo?: string;
}

export default function loginHandler(config: IAuth0Settings) {
  return async (req: NextApiRequest, res: NextApiResponse /*, options?: LoginOptions */): Promise<void> => {
    if (req.query.redirectTo) {
      if (typeof req.query.redirectTo !== 'string') {
        throw new Error('Invalid value provided for redirectTo, must be a string');
      }

      if (!isSafeRedirect(req.query.redirectTo)) {
        throw new Error('Invalid value provided for redirectTo, must be a relative url');
      }
    }

    // new RequestContext(config, req, res),
    const resOidc = new ResponseContext(config, req, res);

    await (resOidc as any).login({ returnTo: req.query.redirectTo });
  };
}
