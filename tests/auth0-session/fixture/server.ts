import { createServer, IncomingMessage, Server, ServerResponse } from 'http';
import url from 'url';
import nock from 'nock';
import { TokenSet } from 'openid-client';
import onHeaders from 'on-headers';
import bodyParser from 'body-parser';
import {
  loginHandler,
  getConfig,
  ConfigParameters,
  clientFactory,
  TransientCookieHandler,
  CookieStore,
  SessionCache,
  logoutHandler,
  callbackHandler
} from '../../../src/auth0-session';
import wellKnown from './well-known.json';
import { jwks } from './cert';

class TestSessionCache implements SessionCache {
  public cache: WeakMap<IncomingMessage, TokenSet>;
  constructor() {
    this.cache = new WeakMap<IncomingMessage, TokenSet>();
  }
  create(req: IncomingMessage, tokenSet: TokenSet): void {
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
}

type Handlers = {
  handleLogin: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleLogout: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleCallback: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleProfile: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
};

const createHandlers = (params: ConfigParameters): Handlers => {
  const config = getConfig(params);
  const getClient = clientFactory(config);
  const transientHandler = new TransientCookieHandler(config);
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
    handleLogin: applyCookies(loginHandler(config, getClient, transientHandler)),
    handleLogout: applyCookies(logoutHandler(config, getClient, sessionCache)),
    handleCallback: applyCookies(callbackHandler(config, getClient, sessionCache, transientHandler)),
    handleProfile: applyCookies((req: IncomingMessage, res: ServerResponse) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(sessionCache.cache.get(req)?.claims()));
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

const requestListener = (handlers: Handlers) => async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
  const { pathname } = url.parse(req.url as string, true);

  const parsedReq = await parseJson(req, res);

  try {
    switch (pathname) {
      case '/login':
        return await handlers.handleLogin(parsedReq, res);
      case '/logout':
        return await handlers.handleLogout(parsedReq, res);
      case '/callback':
        return await handlers.handleCallback(parsedReq, res);
      case '/me':
        return await handlers.handleProfile(parsedReq, res);
      default:
        console.error(404);
    }
  } catch (e) {
    res.writeHead(e.statusCode || 500, e.message);
    res.end();
  }
};

let server: Server;

export const setup = (params: ConfigParameters): Promise<Server> => {
  nock('https://op.example.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, wellKnown);

  nock('https://op.example.com', { allowUnmocked: true }).persist().get('/.well-known/jwks.json').reply(200, jwks);

  server = createServer(requestListener(createHandlers(params)));

  return new Promise((resolve) => server.listen(3000, () => resolve(server)));
};

export const teardown = (): void => {
  nock.cleanAll();
  server && server.close();
};
