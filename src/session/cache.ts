import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import type { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache, AbstractSession } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';
import { NodeRequest, NodeResponse } from '../auth0-session/http';
import {
  Auth0NextApiRequest,
  Auth0NextApiResponse,
  Auth0NextRequestCookies,
  Auth0NextResponseCookies,
  Auth0NextRequest,
  Auth0NextResponse
} from '../http';
import { isNextApiRequest, isRequest } from '../utils/req-helpers';

type Req = IncomingMessage | NextRequest | NextApiRequest;
type Res = ServerResponse | NextResponse | NextApiResponse;

const getAuth0Req = (req: Req) => {
  if (isRequest(req)) {
    return new Auth0NextRequest(req as NextRequest);
  }
  if (isNextApiRequest(req)) {
    return new Auth0NextApiRequest(req as NextApiRequest);
  }
  return new NodeRequest(req as IncomingMessage);
};

const getAuth0Res = (res: Res) => {
  if (typeof Response !== undefined && res instanceof Response) {
    return new Auth0NextResponse(res);
  }
  if ('setPreviewData' in res) {
    return new Auth0NextApiResponse(res);
  }
  return new NodeResponse(res as ServerResponse);
};

export default class SessionCache implements ISessionCache<Req, Res, Session> {
  private cache: WeakMap<Req, Session | null | undefined>;
  private iatCache: WeakMap<Req, number | undefined>;

  constructor(public config: Config, public sessionStore: AbstractSession<Session>) {
    this.cache = new WeakMap();
    this.iatCache = new WeakMap();
  }

  private async init(req: Req, res: Res, autoSave = true): Promise<void> {
    if (!this.cache.has(req)) {
      const [json, iat] = await this.sessionStore.read(getAuth0Req(req));
      this.iatCache.set(req, iat);
      this.cache.set(req, fromJson(json));
      if (this.config.session.rolling && this.config.session.autoSave && autoSave) {
        await this.save(req, res);
      }
    }
  }

  async save(req: Req, res: Res): Promise<void> {
    await this.sessionStore.save(getAuth0Req(req), getAuth0Res(res), this.cache.get(req), this.iatCache.get(req));
  }

  async create(req: Req, res: Res, session: Session): Promise<void> {
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

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
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
  const {
    sessionStore,
    config: {
      session: { rolling, autoSave }
    }
  } = sessionCache;
  const auth0Req = new Auth0NextRequestCookies();
  const [session, iat] = await sessionStore.read(auth0Req);
  if (rolling && autoSave) {
    await set({ session, sessionCache, iat });
  }
  return [session, iat];
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
}) => {
  if (req && res) {
    return sessionCache.set(req, res, session);
  }
  const { sessionStore } = sessionCache;
  await sessionStore.save(new Auth0NextRequestCookies(), new Auth0NextResponseCookies(), session, iat);
};
