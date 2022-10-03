import { getStateMismatchHint, Hint, Hints } from '../../../src/auth0-session/utils/state-mismatch-hint';
import { IncomingMessage } from 'http';
import { Socket } from 'net';
import { CookieConfig } from '../../../src/auth0-session';

type Case = [loginUrl: string, redirectUrl: string, cookieOpts?: Partial<CookieConfig>, issuerBaseUrl?: string];

const cookieConfig = (config?: Partial<CookieConfig>): CookieConfig => ({
  httpOnly: true,
  sameSite: 'lax',
  transient: false,
  ...config
});

const VALID_CASES: Case[] = [
  ['http://localhost:3000/api/auth/login', 'http://localhost:3000/api/auth/callback'],
  ['http://localhost:3000/api/auth/login', 'http://localhost:3000/api/auth/callback'],
  ['http://localhost/api/auth/login', 'http://localhost:3000/api/auth/callback'],
  ['https://www.example.com/login', 'https://www.example.com/callback', { secure: true }],
  ['https://foo.example.com/login', 'https://bar.example.com/callback', { secure: true, domain: '.example.com' }],
  ['http://example.com/foo/login', 'http://example.com/foo/callback', { path: '/foo' }],
  [
    'http://app.example.com/login',
    'http://app.example.com/callback',
    { sameSite: 'strict' },
    'http://auth.example.com/callback'
  ]
];

const INVALID_CASES: [Hints, ...Case][] = [
  [0, 'http://localhost:3000/api/auth/login', 'https://localhost:3000/api/auth/callback'],
  [1, 'https://foo.example.com', 'https://bar.example.com'],
  [1, 'https://example.com', 'https://www.example.com'],
  [2, 'https://foo.example.com/login', 'https://bar.example.com/callback', { secure: true, domain: 'www.example.com' }],
  [3, 'http://example.com/foo/login', 'http://example.com/bar/callback', { path: '/foo' }],
  [4, 'http://www.example.com/login', 'http://www.example.com/callback', { secure: true }],
  [
    5,
    'http://app.example.com/login',
    'http://app.example.com/callback',
    { sameSite: 'strict' },
    'http://auth.idp.com/callback'
  ]
];

const mockRequest = (urlString: string, proxy = false): IncomingMessage => {
  const { pathname, hostname, protocol } = new URL(urlString);
  let headers;
  if (proxy) {
    headers = {
      'x-forwarded-proto': protocol.slice(0, -1),
      'x-forwarded-host': hostname
    };
  }
  return {
    url: pathname,
    headers: {
      host: hostname,
      ...headers
    },
    socket: {
      encrypted: protocol === 'https:'
    } as unknown as Socket
  } as IncomingMessage;
};

describe('state-mismatch-hint', () => {
  it('should provide no hint for valid cases', async () => {
    for (let [login, redirect, cookieOpts, issuer] of VALID_CASES) {
      const hint = getStateMismatchHint(mockRequest(login), redirect, issuer || '', cookieConfig(cookieOpts));
      expect(hint).toBeUndefined();
    }
  });

  it("should provide no hint when the login url can't be derived", async () => {
    const hint = getStateMismatchHint(new IncomingMessage(new Socket()), '', '', cookieConfig({}));
    expect(hint).toBeUndefined();
  });

  it('should provide the correct hint for invalid cases', async () => {
    for (let [type, login, redirect, cookieOpts, issuer] of INVALID_CASES) {
      const hint = getStateMismatchHint(mockRequest(login), redirect, issuer || '', cookieConfig(cookieOpts)) as Hint;
      expect(hint.type).toEqual(type);
    }
  });

  it('should provide no hint for valid cases behind a proxy', async () => {
    for (let [login, redirect, cookieOpts, issuer] of VALID_CASES) {
      const hint = getStateMismatchHint(mockRequest(login, true), redirect, issuer || '', cookieConfig(cookieOpts));
      expect(hint).toBeUndefined();
    }
  });

  it('should provide a hint for invalid cases behind a proxy', () => {
    for (let [type, login, redirect, cookieOpts, issuer] of INVALID_CASES) {
      const hint = getStateMismatchHint(
        mockRequest(login, true),
        redirect,
        issuer || '',
        cookieConfig(cookieOpts)
      ) as Hint;
      expect(hint.type).toEqual(type);
    }
  });

  it('should handle proxy headers as an array', () => {
    const req: IncomingMessage = {
      url: '/foo',
      headers: {
        host: 'http://example.com',
        'x-forwarded-proto': ['http'],
        'x-forwarded-host': ['example.com']
      },
      socket: {
        encrypted: false
      } as unknown as Socket
    } as unknown as IncomingMessage;
    const hint = getStateMismatchHint(req, 'http://example.com/bar', '', cookieConfig({}));
    expect(hint).toBeUndefined();
  });
});
