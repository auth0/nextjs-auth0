/// <reference types="node" />
import { IncomingMessage, ServerResponse } from 'http';
import IAuth0Settings from '../settings';
import CookieSessionStoreSettings from '../session/cookie-store/settings';
export default function logoutHandler(settings: IAuth0Settings, sessionSettings: CookieSessionStoreSettings): (_: IncomingMessage, res: ServerResponse) => Promise<void>;
