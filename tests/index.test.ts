import { IncomingMessage, ServerResponse } from 'http';
import { Socket } from 'net';
import { withoutApi } from './fixtures/default-settings';
import { WithApiAuthRequired, WithPageAuthRequired, InitAuth0, GetSession, ConfigParameters } from '../src';

describe('index', () => {
  let withPageAuthRequired: WithPageAuthRequired,
    withApiAuthRequired: WithApiAuthRequired,
    initAuth0: InitAuth0,
    getSession: GetSession;
  let env: NodeJS.ProcessEnv;

  const updateEnv = (opts: ConfigParameters) => {
    process.env = {
      ...env,
      AUTH0_ISSUER_BASE_URL: opts.issuerBaseURL,
      AUTH0_CLIENT_ID: opts.clientID,
      AUTH0_CLIENT_SECRET: opts.clientSecret,
      AUTH0_BASE_URL: opts.baseURL,
      AUTH0_SECRET: opts.secret as string
    };
  };

  beforeEach(async () => {
    env = process.env;
    ({ withPageAuthRequired, withApiAuthRequired, initAuth0, getSession } = await import('../src'));
  });

  afterEach(() => {
    process.env = env;
    jest.resetModules();
  });

  test('withPageAuthRequired should not create an SDK instance at build time', () => {
    process.env = { ...env, AUTH0_SECRET: undefined };
    expect(() => withApiAuthRequired(jest.fn())).toThrow('"secret" is required');
    expect(() => withPageAuthRequired()).not.toThrow();
  });

  test('should error when mixing named exports and own instance', async () => {
    const instance = initAuth0(withoutApi);
    const req = new IncomingMessage(new Socket());
    const res = new ServerResponse(req);
    await expect(instance.getSession(req, res)).resolves.toBeNull();
    expect(() => getSession(req, res)).toThrow(
      "You cannot mix creating your own instance with `initAuth0` and using named exports like `import { handleAuth } from '@auth0/nextjs-auth0'`"
    );
  });

  test('should error when mixing own instance and named exports', async () => {
    updateEnv(withoutApi);
    const req = new IncomingMessage(new Socket());
    const res = new ServerResponse(req);
    await expect(getSession(req, res)).resolves.toBeNull();
    expect(() => initAuth0()).toThrow(
      "You cannot mix creating your own instance with `initAuth0` and using named exports like `import { handleAuth } from '@auth0/nextjs-auth0'`"
    );
  });

  test('should share instance when using named exports', async () => {
    updateEnv(withoutApi);
    const req = new IncomingMessage(new Socket());
    const res = new ServerResponse(req);
    await expect(getSession(req, res)).resolves.toBeNull();
    await expect(getSession(req, res)).resolves.toBeNull();
  });
});
