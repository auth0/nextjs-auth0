import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import type { TokenEndpointResponse } from '../auth0-session';
import {
  SessionCache as ISessionCache,
  AbstractSession,
  StatefulSession,
  StatelessSession,
  isLoggedOut,
  deleteSub
} from '../auth0-session';
import Session, { fromJson, fromTokenEndpointResponse } from './session';
import { Auth0Request, Auth0Response, NodeRequest, NodeResponse } from '../auth0-session/http';
import {
  Auth0NextApiRequest,
  Auth0NextApiResponse,
  Auth0NextRequestCookies,
  Auth0NextResponseCookies,
  Auth0NextRequest,
  Auth0NextResponse
} from '../http';
import { isNextApiRequest, isRequest } from '../utils/req-helpers';
import { GetConfig, NextConfig } from '../config';

type Req = IncomingMessage | NextRequest | NextApiRequest;
type Res = ServerResponse | NextResponse | NextApiResponse;

export const getAuth0ReqRes = (req: Req, res: Res): [Auth0Request, Auth0Response] => {
  if (isRequest(req)) {
    return [new Auth0NextRequest(req as NextRequest), new Auth0NextResponse(res as NextResponse)];
  }
  if (isNextApiRequest(req)) {
    return [new Auth0NextApiRequest(req as NextApiRequest), new Auth0NextApiResponse(res as NextApiResponse)];
  }
  return [new NodeRequest(req as IncomingMessage), new NodeResponse(res as ServerResponse)];
};

export default class SessionCache implements ISessionCache<Req, Res, Session> {
  private cache: WeakMap<Req, Session | null | undefined>;
  private iatCache: WeakMap<Req, number | undefined>;
  private sessionStore?: AbstractSession<Session>;

  constructor(public getConfig: GetConfig) {
    this.cache = new WeakMap();
    this.iatCache = new WeakMap();
  }

  public getSessionStore(config: NextConfig): AbstractSession<Session> {
    if (!this.sessionStore) {
      this.sessionStore = config.session.store
        ? new StatefulSession<Session>(config)
        : new StatelessSession<Session>(config);
    }
    return this.sessionStore;
  }

  private async init(req: Req, res: Res, autoSave = true): Promise<void> {
    if (!this.cache.has(req)) {
      const [auth0Req] = getAuth0ReqRes(req, res);
      const config = await this.getConfig(auth0Req);
      const sessionStore = this.getSessionStore(config);
      const [json, iat] = await sessionStore.read(auth0Req);
      const session = fromJson(json);
      if (session && config.backchannelLogout && (await isLoggedOut(session.user, config))) {
        this.cache.set(req, null);
        await this.save(req, res);
      } else {
        this.iatCache.set(req, iat);
        this.cache.set(req, session);
        if (config.session.rolling && config.session.autoSave && autoSave) {
          await this.save(req, res);
        }
      }
    }
  }

  async save(req: Req, res: Res): Promise<void> {
    const [auth0Req, auth0Res] = getAuth0ReqRes(req, res);
    const config = await this.getConfig(auth0Req);
    const sessionStore = this.getSessionStore(config);
    await sessionStore.save(auth0Req, auth0Res, this.cache.get(req), this.iatCache.get(req));
  }

  async create(req: Req, res: Res, session: Session): Promise<void> {
    const [auth0Req] = getAuth0ReqRes(req, res);
    const config = await this.getConfig(auth0Req);
    if (config.backchannelLogout) {
      await deleteSub(session.user.sub, config);
    }
    this.cache.set(req, session);
    await this.save(req, res);
  }

  async delete(req: Req, res: Res): Promise<void> {
    await this.init(req, res, false);
    this.cache.set(req, null);
    await this.save(req, res);
  }

  async isAuthenticated(req: Req, res: Res): Promise<boolean> {
    await this.init(req, res);
    const session = this.cache.get(req);
    return !!session?.user;
  }

  async getIdToken(req: Req, res: Res): Promise<string | undefined> {
    await this.init(req, res);
    const session = this.cache.get(req);
    return session?.idToken;
  }

  async set(req: Req, res: Res, session: Session | null | undefined): Promise<void> {
    await this.init(req, res, false);
    this.cache.set(req, session);
    await this.save(req, res);
  }

  async get(req: Req, res: Res): Promise<Session | null | undefined> {
    await this.init(req, res);
    return this.cache.get(req);
  }

  async fromTokenEndpointResponse(req: Req, res: Res, tokenSet: TokenEndpointResponse): Promise<Session> {
    const [auth0Req] = getAuth0ReqRes(req, res);
    const config = await this.getConfig(auth0Req);
    return fromTokenEndpointResponse(tokenSet, config);
  }
}

export const get = async ({
  sessionCache,
  req,
  res
}: {
  sessionCache: SessionCache;
  req?: Req;
  res?: Res;
}): Promise<[(Session | null)?, number?]> => {
  if (req && res) {
    return [await sessionCache.get(req, res)];
  }
  const auth0Req = new Auth0NextRequestCookies();
  const config = await sessionCache.getConfig(auth0Req);
  const sessionStore = sessionCache.getSessionStore(config);
  const {
    session: { rolling, autoSave }
  } = config;
  const [json, iat] = await sessionStore.read(auth0Req);
  const session = fromJson(json);
  if (session && config.backchannelLogout && (await isLoggedOut(session.user, config))) {
    await set({ session: null, sessionCache });
    return [];
  } else {
    if (rolling && autoSave) {
      await set({ session, sessionCache, iat });
    }
    return [session, iat];
  }
};

export const set = async ({
  session,
  sessionCache,
  iat,
  req,
  res
}: {
  session?: Session | null;
  sessionCache: SessionCache;
  iat?: number;
  req?: Req;
  res?: Res;
}): Promise<void> => {
  if (req && res) {
    return sessionCache.set(req, res, session);
  }
  const auth0Req = new Auth0NextRequestCookies();
  const config = await sessionCache.getConfig(auth0Req);
  const sessionStore = sessionCache.getSessionStore(config);
  await sessionStore.save(auth0Req, new Auth0NextResponseCookies(), session, iat);
};
