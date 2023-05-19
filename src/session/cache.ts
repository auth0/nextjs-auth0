import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import type { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache, AbstractSession } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';
import { NodeRequest, NodeResponse } from '../auth0-session/http';
import { Auth0NextApiRequest, Auth0NextApiResponse, Auth0NextRequest, Auth0NextResponse } from '../http';

type Req = IncomingMessage | NextRequest | NextApiRequest;
type Res = ServerResponse | NextResponse | NextApiResponse;
const getAuth0Req = (req: Req) => {
  if (req instanceof Request) {
    return new Auth0NextRequest(req);
  }
  if ('previewData' in req) {
    return new Auth0NextApiRequest(req);
  }
  return new NodeRequest(req);
};

const getAuth0Res = (res: Res) => {
  if (res instanceof Response) {
    return new Auth0NextResponse(res);
  }
  if ('setPreviewData' in res) {
    return new Auth0NextApiResponse(res);
  }
  return new NodeResponse(res);
};

export default class SessionCache implements ISessionCache<Req, Res, Session> {
  private cache: WeakMap<Req, Session | null>;
  private iatCache: WeakMap<Req, number | undefined>;

  constructor(private config: Config, private sessionStore: AbstractSession<Session>) {
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

  async set(req: Req, res: Res, session: Session | null): Promise<void> {
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
