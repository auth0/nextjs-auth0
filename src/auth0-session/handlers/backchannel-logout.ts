import { Auth0Request, Auth0Response } from '../http';
import { Config, GetConfig } from '../config';
import { GetClient } from '../client/abstract-client';
import getLogoutTokenVerifier from '../utils/logout-token-verifier';
import * as querystring from 'querystring';

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
    let body = await req.getBody();
    if (typeof body === 'string') {
      try {
        body = querystring.parse(body) as Record<string, string>;
      } catch (e) {
        body = {};
      }
    }
    const logoutToken = (body as Record<string, string>).logout_token;
    if (!logoutToken) {
      throw new Error('Missing Logout Token');
    }
    const token = await verifyLogoutToken(logoutToken, config, await client.getIssuerMetadata());
    const {
      clientID,
      session: { absoluteDuration, rolling: rollingEnabled, rollingDuration, store },
      backchannelLogout
    } = config;
    const backchannelLogoutStore = typeof backchannelLogout === 'boolean' ? store! : backchannelLogout.store;
    const maxAge =
      (rollingEnabled
        ? Math.min(absoluteDuration as number, rollingDuration as number)
        : (absoluteDuration as number)) * 1000;
    const now = (Date.now() / 1000) | 0;
    const payload = {
      header: { iat: now, uat: now, exp: now + maxAge, maxAge },
      data: {}
    };
    const { sid, sub } = token;
    await Promise.all([
      sid && backchannelLogoutStore.set(`sid|${clientID}|${sid}`, payload),
      sub && backchannelLogoutStore.set(`sub|${clientID}|${sub}`, payload)
    ]);
    res.send204();
  };
}

export type IsLoggedOut = (user: { [key: string]: any }, config: Config) => Promise<boolean>;

export const isLoggedOut: IsLoggedOut = async (user, config) => {
  const {
    clientID,
    session: { store },
    backchannelLogout
  } = config;
  const backchannelLogoutStore = typeof backchannelLogout === 'boolean' ? store! : backchannelLogout.store;
  const { sid, sub } = user;
  const [logoutSid, logoutSub] = await Promise.all([
    backchannelLogoutStore.get(`sid|${clientID}|${sid}`),
    backchannelLogoutStore.get(`sub|${clientID}|${sub}`)
  ]);
  return !!(logoutSid || logoutSub);
};
