import { AddressInfo } from 'net';
import { createServer as createHttpServer, IncomingMessage, Server as HttpServer, ServerResponse } from 'http';
import { createServer as createHttpsServer, Server as HttpsServer } from 'https';
import url from 'url';
import nock from 'nock';
import { TokenSet, TokenSetParameters } from 'openid-client';
import {
  loginHandler,
  getConfig,
  ConfigParameters,
  TransientStore,
  StatelessSession,
  SessionCache,
  logoutHandler,
  callbackHandler,
  LoginOptions,
  LogoutOptions,
  CallbackOptions,
  StatefulSession,
  AbstractSession
} from '../../../src/auth0-session';
import wellKnown from './well-known.json';
import { jwks } from './cert';
import { cert, key } from './https';
import { Claims } from '../../../src/session';
import version from '../../../src/version';
import { NodeRequest, NodeResponse } from '../../../src/auth0-session/http';
import { clientGetter } from '../../../src/auth0-session/client/node-client';
import backchannelLogoutHandlerFactory from '../../../src/auth0-session/handlers/backchannel-logout';
import { promisify } from 'util';

export type SessionResponse = TokenSetParameters & { claims: Claims };

interface NodeCallbackOptions extends Omit<CallbackOptions, 'afterCallback'> {
  afterCallback?: (
    req: IncomingMessage,
    res: ServerResponse,
    session: any,
    state?: Record<string, any>
  ) => Promise<any> | any | undefined;
}

class TestSessionCache implements SessionCache<IncomingMessage, ServerResponse> {
  constructor(private cookieStore: AbstractSession<any>) {}
  async create(req: IncomingMessage, res: ServerResponse, tokenSet: TokenSet): Promise<void> {
    await this.cookieStore.save(new NodeRequest(req), new NodeResponse(res), tokenSet);
  }
  async delete(req: IncomingMessage, res: ServerResponse): Promise<void> {
    await this.cookieStore.save(new NodeRequest(req), new NodeResponse(res), null);
  }
  async isAuthenticated(req: IncomingMessage): Promise<boolean> {
    const [session] = await this.cookieStore.read(new NodeRequest(req));
    return !!session?.id_token;
  }
  async getIdToken(req: IncomingMessage): Promise<string | undefined> {
    const [session] = await this.cookieStore.read(new NodeRequest(req));
    return session?.id_token;
  }
  async fromTokenEndpointResponse(
    _req: IncomingMessage,
    _res: ServerResponse,
    tokenSet: TokenSet
  ): Promise<{ [p: string]: any }> {
    return tokenSet;
  }
}

type Handlers = {
  handleLogin: (req: NodeRequest, res: NodeResponse, opts?: LoginOptions) => Promise<void>;
  handleLogout: (req: NodeRequest, res: NodeResponse, opts?: LogoutOptions) => Promise<void>;
  handleCallback: (req: NodeRequest, res: NodeResponse, opts?: CallbackOptions) => Promise<void>;
  handleBackchannelLogout: (req: NodeRequest, res: NodeResponse) => Promise<void>;
  handleSession: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
};

const createHandlers = (params: ConfigParameters): Handlers => {
  const config = getConfig(params);
  const getClient = clientGetter({ name: 'nextjs-auth0', version });
  const transientStore = new TransientStore(config);
  const cookieStore = params.session?.store ? new StatefulSession<any>(config) : new StatelessSession<any>(config);
  const sessionCache = new TestSessionCache(cookieStore);

  return {
    handleLogin: loginHandler(config, getClient, transientStore),
    handleLogout: logoutHandler(config, getClient, sessionCache),
    handleCallback: callbackHandler(config, getClient, sessionCache, transientStore),
    handleBackchannelLogout: backchannelLogoutHandlerFactory(config, getClient),
    handleSession: async (req: IncomingMessage, res: ServerResponse) => {
      const nodeReq = new NodeRequest(req);
      const [json, iat] = await cookieStore.read(nodeReq);
      if (!json?.id_token) {
        res.writeHead(401);
        res.end();
        return;
      }
      const session = new TokenSet(json);
      await cookieStore.save(nodeReq, new NodeResponse(res), session, iat);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ...session, claims: session?.claims() } as SessionResponse));
    }
  };
};

export const parseJson = async (req: IncomingMessage, res: ServerResponse): Promise<IncomingMessage> => {
  const { default: bodyParser } = await import('body-parser');
  const jsonParser = promisify(bodyParser.json());
  const formParser = promisify(bodyParser.urlencoded({ extended: true }));
  if (req.headers['content-type'] === 'application/json') {
    await jsonParser(req, res);
  } else {
    await formParser(req, res);
  }
  return req;
};

const requestListener =
  (
    handlers: Handlers,
    {
      callbackOptions: nodeCallbackOptions,
      loginOptions,
      logoutOptions
    }: { callbackOptions?: NodeCallbackOptions; loginOptions?: LoginOptions; logoutOptions?: LogoutOptions }
  ) =>
  async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const { pathname } = url.parse(req.url as string, true);
    const parsedReq = await parseJson(req, res);
    const nodeReq = new NodeRequest(parsedReq);
    const nodeRes = new NodeResponse(res);
    let callbackOptions: CallbackOptions | undefined = undefined;
    if (nodeCallbackOptions?.afterCallback) {
      const fn = nodeCallbackOptions.afterCallback;
      callbackOptions = {
        ...nodeCallbackOptions,
        afterCallback: (...args) => fn(req, res, ...args)
      };
    }

    try {
      switch (pathname) {
        case '/login':
          return await handlers.handleLogin(nodeReq, nodeRes, loginOptions);
        case '/logout':
          return await handlers.handleLogout(nodeReq, nodeRes, logoutOptions);
        case '/callback':
          return await handlers.handleCallback(
            nodeReq,
            nodeRes,
            (callbackOptions || nodeCallbackOptions) as CallbackOptions
          );
        case '/backchannel-logout':
          return await handlers.handleBackchannelLogout(nodeReq, nodeRes);
        case '/session':
          return await handlers.handleSession(req, res);
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
    callbackOptions?: NodeCallbackOptions;
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

  if (https) {
    server = createHttpsServer(
      {
        cert,
        key,
        rejectUnauthorized: false
      },
      listen
    );
  } else {
    server = createHttpServer(listen);
  }

  const port = await new Promise((resolve) => server.listen(0, () => resolve((server.address() as AddressInfo).port)));
  const baseURL = `http${https ? 's' : ''}://localhost:${port}`;

  listener =
    customListener ||
    requestListener(createHandlers({ ...params, baseURL }), { callbackOptions, loginOptions, logoutOptions });
  return baseURL;
};

export const teardown = (): Promise<void> | void => {
  nock.restore();
  nock.cleanAll();
  if (server) {
    return new Promise((resolve) => server.close(resolve as (err?: Error) => void));
  }
};
