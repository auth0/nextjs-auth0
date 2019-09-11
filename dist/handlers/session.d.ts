/// <reference types="node" />
import { IncomingMessage } from 'http';
import { ISession } from '../session/session';
import { ISessionStore } from '../session/store';
export default function sessionHandler(sessionStore: ISessionStore): (req: IncomingMessage) => Promise<ISession | null | undefined>;
