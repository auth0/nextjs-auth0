import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import type { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache, CookieStore } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';

export default class SessionCache<
  Req extends object = IncomingMessage | NextApiRequest,
  Res extends object = ServerResponse | NextApiResponse
> implements ISessionCache
{
  private cache: WeakMap<Req, Session | null>;
  private iatCache: WeakMap<Req, number | undefined>;

  constructor(private config: Config, private cookieStore: CookieStore<Req, Res>) {
    this.cache = new WeakMap();
    this.iatCache = new WeakMap();
  }

  private async init(req: Req, res: Res, autoSave = true): Promise<void> {
    if (!this.cache.has(req)) {
      const [json, iat] = await this.cookieStore.read(req);
      this.iatCache.set(req, iat);
      this.cache.set(req, fromJson(json));
      if (this.config.session.rolling && autoSave) {
        await this.save(req, res);
      }
    }
  }

  async save(req: Req, res: Res): Promise<void> {
    await this.cookieStore.save(req, res, this.cache.get(req), this.iatCache.get(req));
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
