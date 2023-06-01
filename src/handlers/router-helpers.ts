import { NextRequest } from 'next/server';
import { NextApiRequest, NextApiResponse } from 'next';

export type AppRouteHandlerFnContext = {
  params: Record<string, string | string[]>;
};

/**
 * Handler function for app routes.
 */
export type AppRouteHandlerFn<Options = any> = (
  /**
   * Incoming request object.
   */
  req: NextRequest,
  /**
   * Context properties on the request (including the parameters if this was a
   * dynamic route).
   */
  ctx: AppRouteHandlerFnContext,

  opts?: Options
) => Promise<Response> | Response;

/**
 * Handler function for app routes.
 */
export type PageRouteHandlerFn<Options> = (
  /**
   * Incoming request object.
   */
  req: NextApiRequest,
  /**
   * Context properties on the request (including the parameters if this was a
   * dynamic route).
   */
  res: NextApiResponse,

  opts?: Options
) => Promise<void> | void;

export type OptionsProvider<Opts> = (req: NextApiRequest | NextRequest) => Opts;

export type AuthHandler<Opts> = Handler<Opts> & {
  (provider?: OptionsProvider<Opts>): Handler<Opts>;
  (options?: Opts): Handler<Opts>;
};

export type Handler<Opts = any> = {
  (req: NextRequest, ctx: AppRouteHandlerFnContext, options?: Opts): Promise<Response> | Response;
  (req: NextApiRequest, res: NextApiResponse, options?: Opts): Promise<unknown> | unknown;
  (req: NextApiRequest | NextRequest, resOrOpts: NextApiResponse | AppRouteHandlerFnContext, options?: Opts):
    | Promise<Response | unknown>
    | Response
    | unknown;
};

export const getHandler =
  <Opts extends object>(appRouteHandler: AppRouteHandlerFn<Opts>, pageRouteHandler: PageRouteHandlerFn<Opts>) =>
  (
    reqOrOptions: NextApiRequest | NextRequest | Opts,
    resOrCtx: NextApiResponse | AppRouteHandlerFnContext,
    options?: Opts
  ) => {
    if (reqOrOptions instanceof Request) {
      return appRouteHandler(reqOrOptions, resOrCtx as AppRouteHandlerFnContext, options);
    }
    if ('socket' in reqOrOptions) {
      return pageRouteHandler(reqOrOptions, resOrCtx as NextApiResponse, options);
    }
    return (req: NextApiRequest | NextRequest, resOrCtxInner: NextApiResponse | AppRouteHandlerFnContext) => {
      const opts = typeof reqOrOptions === 'function' ? (reqOrOptions as OptionsProvider<Opts>)(req) : reqOrOptions;

      if (req instanceof Request) {
        return appRouteHandler(req as NextRequest, resOrCtxInner as AppRouteHandlerFnContext, opts);
      }
      return pageRouteHandler(req as NextApiRequest, resOrCtxInner as NextApiResponse, opts);
    };
  };
