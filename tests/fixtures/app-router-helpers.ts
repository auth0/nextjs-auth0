import nock from 'nock';
import {
  Auth0Server,
  CallbackOptions,
  Claims,
  ConfigParameters,
  initAuth0,
  LoginOptions,
  LogoutOptions,
  ProfileOptions
} from '../../src';
import { withApi } from './default-settings';
import { setupNock } from './setup';
import { NextRequest, NextResponse } from 'next/server';
import { StatelessSession } from '../../src/auth0-session';
import { getConfig } from '../../src/config';
import { Auth0NextRequest } from '../../src/http';
import { encodeState } from '../../src/auth0-session/utils/encoding';
import { signCookie } from '../auth0-session/fixtures/helpers';

export type GetResponseOpts = {
  url: string;
  config?: ConfigParameters;
  cookies?: { [key: string]: string };
  idTokenClaims?: Claims;
  discoveryOptions?: Record<string, string>;
  userInfoPayload?: Record<string, string>;
  userInfoToken?: string;
  callbackOpts?: CallbackOptions;
  loginOpts?: LoginOptions;
  logoutOpts?: LogoutOptions;
  profileOpts?: ProfileOptions;
  extraHandlers?: any;
  clearNock?: boolean;
  auth0Instance?: Auth0Server;
};

export type LoginOpts = Omit<GetResponseOpts, 'url'>;

export const getResponse = async ({
  url,
  config,
  cookies,
  idTokenClaims,
  discoveryOptions,
  userInfoPayload,
  userInfoToken,
  callbackOpts,
  loginOpts,
  logoutOpts,
  profileOpts,
  extraHandlers,
  clearNock = true,
  auth0Instance
}: GetResponseOpts) => {
  const opts = { ...withApi, ...config };
  clearNock && nock.cleanAll();
  await setupNock(opts, { idTokenClaims, discoveryOptions, userInfoPayload, userInfoToken });
  const auth0 = url.split('?')[0].split('/').slice(3);
  const instance = auth0Instance || initAuth0(opts);
  const handleAuth = instance.handleAuth({
    ...(callbackOpts && { callback: instance.handleCallback(callbackOpts) }),
    ...(loginOpts && { login: instance.handleLogin(loginOpts) }),
    ...(logoutOpts && { logout: instance.handleLogout(logoutOpts) }),
    ...(profileOpts && { profile: instance.handleProfile(profileOpts) }),
    onError(_req: any, error: any) {
      return new Response(null, { status: error.status || 500, statusText: error.message });
    },
    ...extraHandlers
  });
  let headers = new Headers();
  if (cookies) {
    headers.set(
      'Cookie',
      Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ')
    );
  }
  return handleAuth(new NextRequest(new URL(url, opts.baseURL), { headers }), { params: { auth0 } });
};

export const getSession = async (config: any, res: NextResponse) => {
  const req = new NextRequest('https://example.com');
  res.cookies.getAll().forEach(({ name, value }: { name: string; value: string }) => req.cookies.set(name, value));

  const store = new StatelessSession(getConfig(config).baseConfig);
  const [session] = await store.read(new Auth0NextRequest(req));
  return session;
};

export const login = async (opts: LoginOpts = {}) => {
  const state = encodeState({ returnTo: '/' });
  const res = await getResponse({
    ...opts,
    url: `/api/auth/callback?state=${state}&code=code`,
    cookies: {
      ...opts.cookies,
      state: await signCookie('state', state),
      nonce: await signCookie('nonce', '__test_nonce__')
    }
  });
  return res;
};
