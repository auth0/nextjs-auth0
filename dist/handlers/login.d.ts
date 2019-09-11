/// <reference types="node" />
import { IncomingMessage, ServerResponse } from 'http';
import IAuth0Settings from '../settings';
import { IOidcClientFactory } from '../utils/oidc-client';
export default function loginHandler(settings: IAuth0Settings, clientProvider: IOidcClientFactory): (_req: IncomingMessage, res: ServerResponse) => Promise<void>;
