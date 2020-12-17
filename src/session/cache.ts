import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { TokenSet } from 'openid-client';
import onHeaders from 'on-headers';
import { Config, SessionCache as ISessionCache, CookieStore } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';

type NextApiOrPageRequest = IncomingMessage | NextApiRequest;
type NextApiOrPageResponse = ServerResponse | NextApiResponse;

export default class SessionCache implements ISessionCache {
  private cache: WeakMap<NextApiOrPageRequest, Session | null>;

  constructor(private config: Config, private cookieStore: CookieStore) {
    this.cache = new WeakMap();
  }

  init(req: NextApiOrPageRequest, res: NextApiOrPageResponse): void {
    if (!this.cache.has(req)) {
      const [json, iat] = this.cookieStore.read(req);
      this.cache.set(req, fromJson(json));
      onHeaders(res, () => this.cookieStore.save(req, res, this.cache.get(req), iat));
    }
  }

  create(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session): void {
    this.cache.set(req, session);
    onHeaders(res, () => this.cookieStore.save(req, res, this.cache.get(req)));
  }

  delete(req: NextApiOrPageRequest, res: NextApiOrPageResponse): void {
    this.init(req, res);
    this.cache.set(req, null);
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
    this.init(req, res);
    this.cache.set(req, session);
  }

  get(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Session | null | undefined {
    this.init(req, res);
    return this.cache.get(req);
  }

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
  }
}
