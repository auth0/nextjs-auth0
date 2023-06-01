import { CallbackOptions, Claims, ConfigParameters, initAuth0 } from '../../src';
import { withApi } from './default-settings';
import { setupNock } from './setup';
import { NextRequest, NextResponse } from 'next/server';
import { StatelessSession } from '../../src/auth0-session';
import { getConfig } from '../../src/config';
import { Auth0NextRequest } from '../../src/http';

export const getResponse = async ({
  url,
  config,
  cookies,
  idTokenClaims,
  callbackOpts,
  extraHandlers
}: {
  url: string;
  config?: ConfigParameters;
  cookies?: { [key: string]: string };
  idTokenClaims?: Claims;
  callbackOpts?: CallbackOptions;
  extraHandlers?: any;
}) => {
  const opts = { ...withApi, ...config };
  await setupNock(opts, { idTokenClaims });
  const auth0 = url.split('?')[0].split('/').slice(3);
  const instance = initAuth0(opts);
  const handleAuth = instance.handleAuth({
    ...(callbackOpts && { callback: instance.handleCallback(callbackOpts) }),
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
