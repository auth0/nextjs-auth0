import { AddressInfo } from 'net';
import { createServer as createHttpServer, IncomingMessage, Server as HttpServer, ServerResponse } from 'http';
import { createServer as createHttpsServer, Server as HttpsServer } from 'https';
import url from 'url';
import nock from 'nock';
import { TokenSet, TokenSetParameters } from 'openid-client';
import onHeaders from 'on-headers';
import bodyParser from 'body-parser';
import {
  loginHandler,
  getConfig,
  ConfigParameters,
  clientFactory,
  TransientStore,
  CookieStore,
  SessionCache,
  logoutHandler,
  callbackHandler,
  LoginOptions,
  LogoutOptions,
  CallbackOptions
} from '../../../src/auth0-session';
import wellKnown from './well-known.json';
import { jwks } from './cert';
import { cert, key } from './https';
import { Claims } from '../../../src/session';
import version from '../../../src/version';

export type SessionResponse = TokenSetParameters & { claims: Claims };

class TestSessionCache implements SessionCache {
  public cache: WeakMap<IncomingMessage, TokenSet>;
  constructor() {
    this.cache = new WeakMap<IncomingMessage, TokenSet>();
  }
  create(req: IncomingMessage, _res: ServerResponse, tokenSet: TokenSet): void {
    this.cache.set(req, tokenSet);
  }
  delete(req: IncomingMessage): void {
    this.cache.delete(req);
  }
  isAuthenticated(req: IncomingMessage): boolean {
    return !!this.cache.get(req)?.id_token;
  }
  getIdToken(req: IncomingMessage): string | undefined {
    return this.cache.get(req)?.id_token;
  }
  fromTokenSet(tokenSet: TokenSet): { [p: string]: any } {
    return tokenSet;
  }
}

type Handlers = {
  handleLogin: (req: IncomingMessage, res: ServerResponse, opts?: LoginOptions) => Promise<void>;
  handleLogout: (req: IncomingMessage, res: ServerResponse, opts?: LogoutOptions) => Promise<void>;
  handleCallback: (req: IncomingMessage, res: ServerResponse, opts?: CallbackOptions) => Promise<void>;
  handleSession: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
};

const createHandlers = (params: ConfigParameters): Handlers => {
  const config = getConfig(params);
  const getClient = clientFactory(config, { name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(config);
  const cookieStore = new CookieStore(config);
  const sessionCache = new TestSessionCache();

  const applyCookies = (fn: Function) => (req: IncomingMessage, res: ServerResponse, ...args: []): any => {
    if (!sessionCache.cache.has(req)) {
      const [json, iat] = cookieStore.read(req);
      sessionCache.cache.set(req, new TokenSet(json));
      onHeaders(res, () => cookieStore.save(req, res, sessionCache.cache.get(req), iat));
    }
    return fn(req, res, ...args);
  };

  return {
    handleLogin: applyCookies(loginHandler(config, getClient, transientStore)),
    handleLogout: applyCookies(logoutHandler(config, getClient, sessionCache)),
    handleCallback: applyCookies(callbackHandler(config, getClient, sessionCache, transientStore)),
    handleSession: applyCookies((req: IncomingMessage, res: ServerResponse) => {
      if (!sessionCache.isAuthenticated(req)) {
        res.writeHead(401);
        res.end();
        return;
      }
      const session = sessionCache.cache.get(req);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ...session, claims: session?.claims() } as SessionResponse));
    })
  };
};

const jsonParse = bodyParser.json();
const parseJson = (req: IncomingMessage, res: ServerResponse): Promise<IncomingMessage> =>
  new Promise((resolve, reject) => {
    jsonParse(req, res, (error: Error | undefined) => {
      if (error) {
        reject(error);
      } else {
        resolve(req);
      }
    });
  });

const requestListener = (
  handlers: Handlers,
  { callbackOptions, loginOptions, logoutOptions }: { callbackOptions?: CallbackOptions; loginOptions?: LoginOptions; logoutOptions?: LogoutOptions }
) => async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
  const { pathname } = url.parse(req.url as string, true);
  const parsedReq = await parseJson(req, res);

  try {
    switch (pathname) {
      case '/login':
        return await handlers.handleLogin(parsedReq, res, loginOptions);
      case '/logout':
        return await handlers.handleLogout(parsedReq, res, logoutOptions);
      case '/callback':
        return await handlers.handleCallback(parsedReq, res, callbackOptions);
      case '/session':
        return await handlers.handleSession(parsedReq, res);
      default:
        res.writeHead(404);
        res.end();
    }
  } catch (e) {
    res.writeHead(e.statusCode || 500, e.message);
    res.end();
  }
};

let server: HttpServer | HttpsServer;

export const setup = async (
  params: Omit<ConfigParameters, 'baseURL'>,
  {
    callbackOptions,
    loginOptions,
    logoutOptions,
    customListener,
    https
  }: {
    https?: boolean;
    callbackOptions?: CallbackOptions;
    loginOptions?: LoginOptions;
    logoutOptions?: LogoutOptions;
    customListener?: (req: IncomingMessage, res: ServerResponse) => void;
  } = {}
): Promise<string> => {
  if (!nock.isActive()) {
    nock.activate();
  }
  nock('https://op.example.com').get('/.well-known/openid-configuration').reply(200, wellKnown);

  nock('https://op.example.com').get('/.well-known/jwks.json').reply(200, jwks);

  nock('https://test.eu.auth0.com')
    .get('/.well-known/openid-configuration')
    .reply(200, { ...wellKnown, issuer: 'https://test.eu.auth0.com/', end_session_endpoint: undefined });

  nock('https://test.eu.auth0.com', { allowUnmocked: true }).persist().get('/.well-known/jwks.json').reply(200, jwks);

  let listener: any = null;
  const listen = (req: IncomingMessage, res: ServerResponse): Promise<void> | null => listener(req, res);

  server = (https ? createHttpsServer : createHttpServer)(
    {
      cert,
      key,
      rejectUnauthorized: false
    },
    listen
  );

  const port = await new Promise((resolve) => server.listen(0, () => resolve((server.address() as AddressInfo).port)));
  const baseURL = `http${https ? 's' : ''}://localhost:${port}`;

  listener = customListener || requestListener(createHandlers({ ...params, baseURL }), { callbackOptions, loginOptions, logoutOptions });
  return baseURL;
};

export const teardown = (): Promise<void> | void => {
  nock.restore();
  nock.cleanAll();
  if (server) {
    return new Promise((resolve) => server.close(resolve as (err?: Error) => void));
  }
};
