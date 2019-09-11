/// <reference types="node" />
import { IncomingMessage, ServerResponse } from 'http';
import IAuth0Settings from '../settings';
import { ISessionStore } from '../session/store';
import { IOidcClientFactory } from '../utils/oidc-client';
import { CallbackOptions } from './callback-options';
export default function callbackHandler(settings: IAuth0Settings, clientProvider: IOidcClientFactory, sessionStore: ISessionStore): (req: IncomingMessage, res: ServerResponse, options?: CallbackOptions | undefined) => Promise<void>;
