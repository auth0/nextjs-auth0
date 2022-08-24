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

  init(req: NextApiOrPageRequest, res: NextApiOrPageResponse, autoSave = true): void {
    if (!this.cache.has(req)) {
      const [json, iat] = this.cookieStore.read(req);
      this.iatCache.set(req, iat);
      this.cache.set(req, fromJson(json));
      if (this.config.session.rolling && autoSave) {
        this.save(req, res);
      }
    }
  }

  save(req: NextApiOrPageRequest, res: NextApiOrPageResponse): void {
    this.cookieStore.save(req, res, this.cache.get(req), this.iatCache.get(req));
  }

  create(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session): void {
    this.cache.set(req, session);
    this.save(req, res);
  }

  delete(req: NextApiOrPageRequest, res: NextApiOrPageResponse): void {
    this.init(req, res, false);
    this.cache.set(req, null);
    this.save(req, res);
  }

  isAuthenticated(req: NextApiOrPageRequest, res: NextApiOrPageResponse): boolean {
    this.init(req, res);
    const session = this.cache.get(req);
    return !!session?.user;
  }

  getIdToken(req: NextApiOrPageRequest, res: NextApiOrPageResponse): string | undefined {
    this.init(req, res);
    const session = this.cache.get(req);
    return session?.idToken;
  }

  set(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session | null): void {
    this.init(req, res, false);
    this.cache.set(req, session);
    this.save(req, res);
  }

  get(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Session | null | undefined {
    this.init(req, res);
    return this.cache.get(req);
  }

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
  }
}
