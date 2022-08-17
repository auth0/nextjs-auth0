import { IncomingMessage } from 'http';
import { TokenSet } from 'openid-client';

export interface SessionCache<Session = { [key: string]: any }, Request = IncomingMessage> {
  create(req: Request, session: Session): void;
  delete(req: Request): void;
  isAuthenticated(req: Request): boolean;
  getIdToken(req: Request): string | undefined;
  fromTokenSet(tokenSet: TokenSet): Session;
}
