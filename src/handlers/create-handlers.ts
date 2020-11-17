import { HandleLogin } from './login';
import { HandleLogout } from './logout';
import { HandleCallback } from './callback';
import { HandleProfile } from './profile';
import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';

export interface Handlers {
  login: HandleLogin;
  logout: HandleLogout;
  callback: HandleCallback;
  profile: HandleProfile;
}

export type CreateHandlers = (userHandlers?: Partial<Handlers>) => NextApiHandler;

const wrapErrorHandling = (fn: NextApiHandler): NextApiHandler => async (
  req: NextApiRequest,
  res: NextApiResponse
): Promise<void> => {
  try {
    await fn(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
};

export default function handlerFactory({
  handleLogin,
  handleLogout,
  handleCallback,
  handleProfile
}: any): CreateHandlers {
  return (userHandlers: Partial<Handlers> = {}): NextApiHandler => {
    const { login, logout, callback, profile } = {
      login: wrapErrorHandling(handleLogin),
      logout: wrapErrorHandling(handleLogout),
      callback: wrapErrorHandling(handleCallback),
      profile: wrapErrorHandling(handleProfile),
      ...userHandlers
    };
    return async (req, res): Promise<void> => {
      const {
        query: { auth0: route }
      } = req;

      switch (route) {
        case 'login':
          return login(req, res);
        case 'logout':
          return logout(req, res);
        case 'callback':
          return callback(req, res);
        case 'me':
          return profile(req, res);
        default:
          res.status(404).end();
      }
    };
  };
}
