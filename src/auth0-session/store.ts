import { IncomingMessage, ServerResponse } from 'http';

export interface Store {
  read(req: IncomingMessage): [{ [key: string]: any }?, number?];
  save(
    req: IncomingMessage,
    res: ServerResponse,
    session: { [key: string]: any } | undefined | null,
    createdAt?: number
  ): void;
}
