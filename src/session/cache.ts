import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache, CookieStore } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';

type NextApiOrPageRequest = IncomingMessage | NextApiRequest;
type NextApiOrPageResponse = ServerResponse | NextApiResponse;

export default class SessionCache implements ISessionCache {
  private cache: WeakMap<NextApiOrPageRequest, Session | null>;
  private iatCache: WeakMap<NextApiOrPageRequest, number | undefined>;

  constructor(private config: Config, private cookieStore: CookieStore) {
    this.cache = new WeakMap();
    this.iatCache = new WeakMap();
  }

  async init(req: NextApiOrPageRequest, res: NextApiOrPageResponse, autoSave = true): Promise<void> {
    if (!this.cache.has(req)) {
      const [json, iat] = await this.cookieStore.read(req);
      this.iatCache.set(req, iat);
      this.cache.set(req, fromJson(json));
      if (this.config.session.rolling && autoSave) {
        await this.save(req, res);
      }
    }
  }

  async save(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<void> {
    await this.cookieStore.save(req, res, this.cache.get(req), this.iatCache.get(req));
  }

  async create(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session): Promise<void> {
    this.cache.set(req, session);
    await this.save(req, res);
  }

  async delete(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<void> {
    await this.init(req, res, false);
    this.cache.set(req, null);
    await this.save(req, res);
  }

  async isAuthenticated(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<boolean> {
    await this.init(req, res);
    const session = this.cache.get(req);
    return !!session?.user;
  }

  async getIdToken(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<string | undefined> {
    await this.init(req, res);
    const session = this.cache.get(req);
    return session?.idToken;
  }

  async set(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session | null): Promise<void> {
    await this.init(req, res, false);
    this.cache.set(req, session);
    await this.save(req, res);
  }

  async get(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<Session | null | undefined> {
    await this.init(req, res);
    return this.cache.get(req);
  }

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
  }
}
