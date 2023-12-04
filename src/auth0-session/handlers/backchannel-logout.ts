import { Auth0Request, Auth0Response } from '../http';
import { Config, GetConfig } from '../config';
import { GetClient } from '../client/abstract-client';
import getLogoutTokenVerifier from '../utils/logout-token-verifier';
import { BackchannelLogoutError } from '../utils/errors';
import { JWTPayload } from 'jose';

const getStore = (config: Config) => {
  const {
    session: { store },
    backchannelLogout
  } = config;
  return typeof backchannelLogout === 'boolean' ? store! : backchannelLogout.store;
};

export type HandleBackchannelLogout = (req: Auth0Request, res: Auth0Response) => Promise<void>;

export default function backchannelLogoutHandlerFactory(
  getConfig: GetConfig,
  getClient: GetClient
): HandleBackchannelLogout {
  const getConfigFn = typeof getConfig === 'function' ? getConfig : () => getConfig;
  const verifyLogoutToken = getLogoutTokenVerifier();
  return async (req, res) => {
    const config = await getConfigFn(req);
    const client = await getClient(config);
    res.setHeader('cache-control', 'no-store');
    const body = new URLSearchParams(await req.getBody());
    const logoutToken = body.get('logout_token');
    if (!logoutToken) {
      throw new BackchannelLogoutError('invalid_request', 'Missing Logout Token');
    }
    let token: JWTPayload;
    try {
      token = await verifyLogoutToken(logoutToken, config, await client.getIssuerMetadata());
    } catch (e) {
      throw new BackchannelLogoutError('invalid_request', e.message);
    }
    const {
      clientID,
      session: { absoluteDuration, rolling: rollingEnabled, rollingDuration }
    } = config;
    const store = getStore(config);
    const maxAge =
      (rollingEnabled
        ? Math.min(absoluteDuration as number, rollingDuration as number)
        : (absoluteDuration as number)) * 1000;
    const now = (Date.now() / 1000) | 0;
    const payload = {
      header: { iat: now, uat: now, exp: now + maxAge, maxAge },
      data: {}
    };
    try {
      const { sid, sub } = token;
      await Promise.all([
        sid && store.set(`sid|${clientID}|${sid}`, payload),
        sub && store.set(`sub|${clientID}|${sub}`, payload)
      ]);
    } catch (e) {
      throw new BackchannelLogoutError('application_error', e.message);
    }
    res.send204();
  };
}

export type IsLoggedOut = (user: { [key: string]: any }, config: Config) => Promise<boolean>;

export const isLoggedOut: IsLoggedOut = async (user, config) => {
  const { clientID } = config;
  const store = getStore(config);
  const { sid, sub } = user;
  const [logoutSid, logoutSub] = await Promise.all([
    store.get(`sid|${clientID}|${sid}`),
    store.get(`sub|${clientID}|${sub}`)
  ]);
  return !!(logoutSid || logoutSub);
};

export type DeleteSub = (sub: string, config: Config) => Promise<void>;

export const deleteSub: DeleteSub = async (sub, config) => {
  const { clientID } = config;
  const store = getStore(config);
  await store.delete(`sub|${clientID}|${sub}`);
};
