import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { TokenSet } from 'openid-client';
import onHeaders from 'on-headers';
import { Config, SessionCache as ISessionCache, Store } from '../auth0-session';
import Session, { fromJson, fromTokenSet } from './session';

type NextApiOrPageRequest = IncomingMessage | NextApiRequest;
type NextApiOrPageResponse = ServerResponse | NextApiResponse;

export default class SessionCache implements ISessionCache {
  private cache: WeakMap<NextApiOrPageRequest, Session | null>;

  constructor(private config: Config, private store: Store) {
    this.cache = new WeakMap();
  }

  async init(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<void> {
    if (!this.cache.has(req)) {
      const [json, iat] = await this.store.read(req);
      this.cache.set(req, fromJson(json));
      onHeaders(res, () => this.store.save(req, res, this.cache.get(req), iat));
    }
  }

  create(req: NextApiOrPageRequest, res: NextApiOrPageResponse, session: Session): void {
    this.cache.set(req, session);
    onHeaders(res, () => this.store.save(req, res, this.cache.get(req)));
  }

  async delete(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<void> {
    await this.init(req, res);
    this.cache.set(req, null);
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
    await this.init(req, res);
    this.cache.set(req, session);
  }

  async get(req: NextApiOrPageRequest, res: NextApiOrPageResponse): Promise<Session | null | undefined> {
    await this.init(req, res);
    return this.cache.get(req);
  }

  fromTokenSet(tokenSet: TokenSet): Session {
    return fromTokenSet(tokenSet, this.config);
  }
}
