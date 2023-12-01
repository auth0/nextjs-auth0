import { NextApiResponse, NextApiRequest } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { HandleBackchannelLogout as BaseHandleBackchannelLogout } from '../auth0-session';
import { Auth0NextApiRequest, Auth0NextApiResponse, Auth0NextRequest, Auth0NextResponse } from '../http';
import { AppRouteHandlerFnContext, Handler, getHandler } from './router-helpers';
import { GetConfig } from '../config';

/**
 * The handler for the POST `/api/auth/backchannel-logout` API route.
 *
 * @category Server
 */
export type HandleBackchannelLogout = Handler;

/**
 * @ignore
 */
export default function handleBackchannelLogoutFactory(
  handler: BaseHandleBackchannelLogout,
  getConfig: GetConfig
): HandleBackchannelLogout {
  const appRouteHandler = appRouteHandlerFactory(handler, getConfig);
  const pageRouteHandler = pageRouteHandlerFactory(handler, getConfig);

  return getHandler(appRouteHandler, pageRouteHandler) as HandleBackchannelLogout;
}

const appRouteHandlerFactory: (
  handler: BaseHandleBackchannelLogout,
  getConfig: GetConfig
) => (req: NextRequest, ctx: AppRouteHandlerFnContext) => Promise<Response> | Response =
  (handler, getConfig) => async (req) => {
    try {
      const auth0Req = new Auth0NextRequest(req);
      const config = await getConfig(auth0Req);
      if (!config.backchannelLogout) {
        return new NextResponse('Back-Channel Logout is not enabled.', { status: 404 });
      }
      const auth0Res = new Auth0NextResponse(new NextResponse());
      await handler(auth0Req, auth0Res);
      return auth0Res.res;
    } catch (e) {
      return NextResponse.json(
        {
          error: e.code || 'unknown_error',
          error_description: e.description || e.message
        },
        { status: 400, headers: { 'cache-control': 'no-store' } }
      );
    }
  };

const pageRouteHandlerFactory: (
  handler: BaseHandleBackchannelLogout,
  getConfig: GetConfig
) => (req: NextApiRequest, res: NextApiResponse) => Promise<void> | void = (handler, getConfig) => async (req, res) => {
  try {
    const auth0Req = new Auth0NextApiRequest(req);
    const config = await getConfig(auth0Req);
    if (!config.backchannelLogout) {
      res.status(404).end('Back-Channel Logout is not enabled.');
      return;
    }
    return await handler(auth0Req, new Auth0NextApiResponse(res));
  } catch (e) {
    res.setHeader('cache-control', 'no-store');
    res.status(400).json({
      error: e.code || 'unknown_error',
      error_description: e.description || e.message
    });
  }
};
