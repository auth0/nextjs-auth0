/// <reference types="node" />
import { IncomingMessage, ServerResponse } from 'http';
import { ISessionStore } from '../store';
import { ISession } from '../session';
import CookieSessionStoreSettings from './settings';
export default class CookieSessionStore implements ISessionStore {
    private settings;
    constructor(settings: CookieSessionStoreSettings);
    /**
     * Read the session from the cookie.
     * @param req HTTP request
     */
    read(req: IncomingMessage): Promise<ISession | null>;
    /**
     * Write the session to the cookie.
     * @param req HTTP request
     */
    save(_: IncomingMessage, res: ServerResponse, session: ISession): Promise<void>;
}
