import { IncomingMessage, ServerResponse } from 'http';
import { TokenSet } from 'openid-client';

export interface SessionCache {
  create(req: IncomingMessage, res: ServerResponse, session: { [key: string]: any }): void;
  delete(req: IncomingMessage, res: ServerResponse): void;
  isAuthenticated(req: IncomingMessage, res: ServerResponse): boolean;
  getIdToken(req: IncomingMessage, res: ServerResponse): string | undefined;
  fromTokenSet(tokenSet: TokenSet): { [key: string]: any };
}
