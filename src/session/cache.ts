import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';
import AbstractCookieStore from '../auth0-session/stores/abstract-cookie-store';
import NodeCookieStore from '../auth0-session/stores/node-cookie-store';
import { NextRequest, NextResponse } from 'next/server';
import MiddlewareCookieStore from '../stores/middleware-cookie-store';

export type NodeSessionCache = SessionCache<
  IncomingMessage | NextApiRequest,
  ServerResponse | NextApiResponse,
  NodeCookieStore
>;
export type MiddlewareSessionCache = SessionCache<NextRequest, NextResponse, MiddlewareCookieStore>;

export default class SessionCache<
  Request extends object,
  Response extends object,
  CookieStore extends AbstractCookieStore
> implements ISessionCache<Session, Request>
{
  private cache: WeakMap<Request, Session | null>;
  private iatCache: WeakMap<Request, number | undefined>;

  constructor(private config: Config, private cookieStore: CookieStore) {
    this.cache = new WeakMap();
    this.iatCache = new WeakMap();
  }

  async init(req: Request): Promise<void> {
    if (!this.cache.has(req)) {
      const [json, iat] = await this.cookieStore.read(req);
      this.iatCache.set(req, iat);
      this.cache.set(req, fromJson(json));
    }
  }

  async save(req: Request, res: Response): Promise<void> {
    await this.cookieStore.save(req, res, this.cache.get(req), this.iatCache.get(req));
  }

  create(req: Request, session: Session): void {
    this.cache.set(req, session);
  }

  delete(req: Request): void {
    this.init(req);
    this.cache.set(req, null);
  }

  isAuthenticated(req: Request): boolean {
    this.init(req);
    const session = this.cache.get(req);
    return !!session?.user;
  }

  getIdToken(req: Request): string | undefined {
    this.init(req);
    const session = this.cache.get(req);
    return session?.idToken;
  }

  set(req: Request, session: Session | null): void {
    this.init(req);
    this.cache.set(req, session);
  }

  get(req: Request): Session | null | undefined {
    this.init(req);
    return this.cache.get(req);
  }

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
  }
}
