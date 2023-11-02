import type React from 'react';
import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { Claims, get, SessionCache } from '../session';
import { assertCtx } from '../utils/assert';
import { ParsedUrlQuery } from 'querystring';
import { GetConfig } from '../config';
import { Auth0NextRequestCookies } from '../http';
import { NodeRequest } from '../auth0-session/http';

/**
 * If you wrap your `getServerSideProps` with {@link WithPageAuthRequired} your props object will be augmented with
 * the user property, which will be the user's {@link Claims}.
 *
 * ```js
 * // pages/profile.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function Profile({ user }) {
 *   return <div>Hello {user.name}</div>;
 * }
 *
 * export const getServerSideProps = withPageAuthRequired();
 * ```
 *
 * @category Server
 */
export type GetServerSidePropsResultWithSession<P = any> = GetServerSidePropsResult<P & { user: Claims }>;

/**
 * A page route that has been augmented with {@link WithPageAuthRequired}.
 *
 * @category Server
 */
export type PageRoute<P, Q extends ParsedUrlQuery = ParsedUrlQuery> = (
  ctx: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResultWithSession<P>>;

/**
 * Objects containing the route parameters and search parameters of th page.
 *
 * @category Server
 */
export type AppRouterPageRouteOpts = {
  params?: Record<string, string | string[]>;
  searchParams?: { [key: string]: string | string[] | undefined };
};

/**
 * An app route that has been augmented with {@link WithPageAuthRequired}.
 *
 * @category Server
 */
export type AppRouterPageRoute = (obj: AppRouterPageRouteOpts) => Promise<React.JSX.Element>;

/**
 * If you have a custom returnTo url you should specify it in `returnTo`.
 *
 * You can pass in your own `getServerSideProps` method, the props returned from this will be
 * merged with the user props. You can also access the user session data by calling `getSession`
 * inside of this method. For example:
 *
 * ```js
 * // pages/protected-page.js
 * import { getSession, withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function ProtectedPage({ user, customProp }) {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = withPageAuthRequired({
 *   // returnTo: '/unauthorized',
 *   async getServerSideProps(ctx) {
 *     // access the user session if needed
 *     // const session = await getSession(ctx.req, ctx.res);
 *     return {
 *       props: {
 *         // customProp: 'bar',
 *       }
 *     };
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type WithPageAuthRequiredPageRouterOptions<
  P extends { [key: string]: any } = { [key: string]: any },
  Q extends ParsedUrlQuery = ParsedUrlQuery
> = {
  getServerSideProps?: GetServerSideProps<P, Q>;
  returnTo?: string;
};

/**
 * Wrap your `getServerSideProps` with this method to make sure the user is authenticated before
 * visiting the page.
 *
 * ```js
 * // pages/protected-page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function ProtectedPage() {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = withPageAuthRequired();
 * ```
 *
 * If the user visits `/protected-page` without a valid session, it will redirect the user to the
 * login page. Then they will be returned to `/protected-page` after login.
 *
 * @category Server
 */
export type WithPageAuthRequiredPageRouter = <
  P extends { [key: string]: any } = { [key: string]: any },
  Q extends ParsedUrlQuery = ParsedUrlQuery
>(
  opts?: WithPageAuthRequiredPageRouterOptions<P, Q>
) => PageRoute<P, Q>;

/**
 * Specify the URL to `returnTo` - this is important in app router pages because the server component
 * won't know the URL of the page.
 *
 * @category Server
 */
export type WithPageAuthRequiredAppRouterOptions = {
  returnTo?: string | ((obj: AppRouterPageRouteOpts) => Promise<string> | string);
};

/**
 * Wrap your Server Component with this method to make sure the user is authenticated before
 * visiting the page.
 *
 * ```js
 * // app/protected-page/page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function withPageAuthRequired(ProtectedPage() {
 *   return <div>Protected content</div>;
 * }, { returnTo: '/protected-page' });
 * ```
 *
 * If the user visits `/protected-page` without a valid session, it will redirect the user to the
 * login page.
 *
 * Note: Server Components are not aware of the req or the url of the page. So if you want the user to return to the
 * page after login, you must specify the `returnTo` option.
 *
 * You can specify a function to `returnTo` that accepts the `params` (An object containing the dynamic
 * route parameters) and `searchParams` (An object containing the search parameters of the current URL)
 * argument from the page, to preserve dynamic routes and search params.
 *
 * ```js
 * // app/protected-page/[slug]/page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function withPageAuthRequired(ProtectedPage() {
 *   return <div>Protected content</div>;
 * }, {
 *   returnTo({ params }) {
 *     return `/protected-page/${params.slug}`
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type WithPageAuthRequiredAppRouter = (
  fn: AppRouterPageRoute,
  opts?: WithPageAuthRequiredAppRouterOptions
) => AppRouterPageRoute;

/**
 * Protects Page router pages {@link WithPageAuthRequiredPageRouter} or
 * App router pages {@link WithPageAuthRequiredAppRouter}
 *
 * @category Server
 */
export type WithPageAuthRequired = WithPageAuthRequiredPageRouter & WithPageAuthRequiredAppRouter;

/**
 * @ignore
 */
export default function withPageAuthRequiredFactory(
  getConfig: GetConfig,
  sessionCache: SessionCache
): WithPageAuthRequired {
  const appRouteHandler = appRouteHandlerFactory(getConfig, sessionCache);
  const pageRouteHandler = pageRouteHandlerFactory(getConfig, sessionCache);

  return ((
    fnOrOpts?: WithPageAuthRequiredPageRouterOptions | AppRouterPageRoute,
    opts?: WithPageAuthRequiredAppRouterOptions
  ) => {
    if (typeof fnOrOpts === 'function') {
      return appRouteHandler(fnOrOpts, opts);
    }
    return pageRouteHandler(fnOrOpts);
  }) as WithPageAuthRequired;
}

/**
 * @ignore
 */
const appRouteHandlerFactory =
  (getConfig: GetConfig, sessionCache: SessionCache): WithPageAuthRequiredAppRouter =>
  (handler, opts = {}) =>
  async (params) => {
    const {
      routes: { login: loginUrl }
    } = await getConfig(new Auth0NextRequestCookies());
    const [session] = await get({ sessionCache });
    if (!session?.user) {
      const returnTo = typeof opts.returnTo === 'function' ? await opts.returnTo(params) : opts.returnTo;
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { redirect } = require('next/navigation');
      redirect(`${loginUrl}${opts.returnTo ? `?returnTo=${returnTo}` : ''}`);
    }
    return handler(params);
  };

/**
 * @ignore
 */
const pageRouteHandlerFactory =
  (getConfig: GetConfig, sessionCache: SessionCache): WithPageAuthRequiredPageRouter =>
  ({ getServerSideProps, returnTo } = {}) =>
  async (ctx) => {
    assertCtx(ctx);
    const {
      routes: { login: loginUrl }
    } = await getConfig(new NodeRequest(ctx.req));
    const session = await sessionCache.get(ctx.req, ctx.res);
    if (!session?.user) {
      return {
        redirect: {
          destination: `${loginUrl}?returnTo=${encodeURIComponent(returnTo || ctx.resolvedUrl)}`,
          permanent: false
        }
      };
    }
    let ret: any = { props: {} };
    if (getServerSideProps) {
      ret = await getServerSideProps(ctx);
    }
    if (ret.props instanceof Promise) {
      return { ...ret, props: ret.props.then((props: any) => ({ user: session.user, ...props })) };
    }
    return { ...ret, props: { user: session.user, ...ret.props } };
  };
