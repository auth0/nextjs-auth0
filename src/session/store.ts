import { NextApiRequest } from 'next';
import { TokenSet } from 'openid-client';
import { Config, SessionCache as ISessionCache } from '../auth0-session';
import Session, { fromTokenSet } from './session';

export default class SessionCache implements ISessionCache {
  private cache: WeakMap<NextApiRequest, Session | null>;

  constructor(private config: Config) {
    this.cache = new WeakMap();
  }

  create(req: NextApiRequest, tokenSet: TokenSet): void {
    this.cache.set(req, fromTokenSet(tokenSet, this.config));
  }

  delete(req: NextApiRequest): void {
    this.set(req, null);
  }

  has(req: NextApiRequest): boolean {
    return this.cache.has(req);
  }

  isAuthenticated(req: NextApiRequest): boolean {
    const session = this.get(req);
    return !!session?.user;
  }

  getIdToken(req: NextApiRequest): string | undefined {
    const session = this.get(req);
    return session?.idToken;
  }

  set(req: NextApiRequest, session: Session | null): void {
    this.cache.set(req, session);
  }

  get(req: NextApiRequest): Session | null | undefined {
    return this.cache.get(req);
  }
}
