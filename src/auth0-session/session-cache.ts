import type { TokenSet } from 'openid-client';

export interface SessionCache<Req = any, Res = any, Session = { [key: string]: any }> {
  create(req: Req, res: Res, session: Session): Promise<void>;
  delete(req: Req, res: Res): Promise<void>;
  isAuthenticated(req: Req, res: Res): Promise<boolean>;
  getIdToken(req: Req, res: Res): Promise<string | undefined>;
  fromTokenSet(tokenSet: TokenSet): Session;
}
