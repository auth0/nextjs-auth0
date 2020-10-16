import { IncomingMessage } from 'http';
import { TokenSet } from 'openid-client';

export interface SessionCache {
  create(req: IncomingMessage, tokenSet: TokenSet): void;
  delete(req: IncomingMessage): void;
  isAuthenticated(req: IncomingMessage): boolean;
  getIdToken(req: IncomingMessage): string | undefined;
}
