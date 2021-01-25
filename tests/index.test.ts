import { IncomingMessage, ServerResponse } from 'http';
import { mocked } from 'ts-jest/utils';
import { Socket } from 'net';

describe('index', () => {
  let _env: { [key: string]: any };
  let initAuth0: any;
  let withPageAuthRequired: any;
  let withApiAuthRequired: any;
  let getSession: any;
  let getAccessToken: any;
  let handleLogin: any;
  let handleLogout: any;
  let handleCallback: any;
  let handleProfile: any;
  let handleAuth: any;

  beforeEach(() => {
    _env = process.env;
    process.env = {
      ...process.env,
      AUTH0_SECRET: '__secret__',
      AUTH0_ISSUER_BASE_URL: 'https://example.com',
      AUTH0_BASE_URL: 'https://example.com',
      AUTH0_CLIENT_ID: '__client_id__',
      AUTH0_CLIENT_SECRET: '__client_secret__'
    };
    ({
      initAuth0,
      withPageAuthRequired,
      withApiAuthRequired,
      getSession,
      getAccessToken,
      handleLogin,
      handleLogout,
      handleCallback,
      handleProfile,
      handleAuth
    } = require('../src'));
  });

  afterEach(() => {
    process.env = _env;
  });

  test('should throw if you call instance methods after a named export', () => {
    const req = mocked(new IncomingMessage(new Socket()));
    const res = mocked(new ServerResponse(req));
    expect(() => getSession(req, res)).not.toThrow();
    expect(() => initAuth0().getSession(req, res)).toThrow(/You are creating multiple instances of the Auth0 SDK/);
  });

  test('should throw if you call a named export after an instance method', () => {
    const req = mocked(new IncomingMessage(new Socket()));
    const res = mocked(new ServerResponse(req));
    expect(() => initAuth0().getSession(req, res)).not.toThrow();
    expect(() => getSession(req, res)).toThrow(/You are creating multiple instances of the Auth0 SDK/);
  });

  test('withPageAuthRequired should not create an SDK instance at build time', () => {
    delete process.env.AUTH0_SECRET;
    expect(() => withApiAuthRequired()).toThrow('"secret" is required');
    expect(() => getAccessToken()).toThrow('"secret" is required');
    expect(() => withApiAuthRequired()).toThrow('"secret" is required');
    expect(() => handleLogin()).toThrow('"secret" is required');
    expect(() => handleLogout()).toThrow('"secret" is required');
    expect(() => handleCallback()).toThrow('"secret" is required');
    expect(() => handleProfile()).toThrow('"secret" is required');
    expect(() => handleAuth()).toThrow('"secret" is required');

    expect(() => withPageAuthRequired()).not.toThrow();
  });

  test('multiple calls to named exports should reuse a single instance', () => {
    const req = mocked(new IncomingMessage(new Socket()));
    const res = mocked(new ServerResponse(req));
    expect(() => getSession(req, res)).not.toThrow();
    expect(() => getSession(req, res)).not.toThrow();
  });
});
