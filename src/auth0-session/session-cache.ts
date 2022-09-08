import type { TokenSet } from 'openid-client';

export interface SessionCache {
  create(req: unknown, res: unknown, session: { [key: string]: any }): Promise<void>;
  delete(req: unknown, res: unknown): Promise<void>;
  isAuthenticated(req: unknown, res: unknown): Promise<boolean>;
  getIdToken(req: unknown, res: unknown): Promise<string | undefined>;
  fromTokenSet(tokenSet: TokenSet): { [key: string]: any };
}
