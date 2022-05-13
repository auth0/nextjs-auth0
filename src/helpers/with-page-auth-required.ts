import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { Claims, SessionCache } from '../session';
import { assertCtx } from '../utils/assert';
import React, { ComponentType } from 'react';
import {
  UserProps,
  WithPageAuthRequiredOptions as WithPageAuthRequiredCSROptions,
  WithPageAuthRequiredProps
} from '../frontend/with-page-auth-required';
import { withPageAuthRequired as withPageAuthRequiredCSR } from '../frontend';
import { ParsedUrlQuery } from 'querystring';

/**
 * If you wrap your `getServerSideProps` with {@link WithPageAuthRequired} your props object will be augmented with
 * the user property, which will be the user's {@link Claims}
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
export type GetServerSidePropsResultWithSession<P = any> = GetServerSidePropsResult<P & { user?: Claims | null }>;

/**
 * A page route that has been augmented with {@link WithPageAuthRequired}
 *
 * @category Server
 */
export type PageRoute<P, Q extends ParsedUrlQuery = ParsedUrlQuery> = (
  cts: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResultWithSession<P>>;

/**
 * If you have a custom returnTo url you should specify it in `returnTo`.
 *
 * You can pass in your own `getServerSideProps` method, the props returned from this will be merged with the
 * user props. You can also access the user session data by calling `getSession` inside of this method, eg:
 *
 * ```js
 * // pages/protected-page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function ProtectedPage({ user, customProp }) {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = withPageAuthRequired({
 *   returnTo: '/foo',
 *   async getServerSideProps(ctx) {
 *     // access the user session
 *     const session = getSession(ctx.req, ctx.res);
 *     return { props: { customProp: 'bar' } };
 *   }
 * });
 * ```
 *
 * If you're using >=Next 12 and {@link getSession} or {@link getAccessToken} without `getServerSideProps`, because you don't want to
 * require authentication on your route, you might get a warning/error: "You should not access 'res' after getServerSideProps resolves".
 * You can work around this by wrapping your `getServerSideProps` in `withPageAuthRequired` using `authRequired: false`, this ensures
 * that the code that accesses `res` will run within the lifecycle of `getServerSideProps`, avoiding the warning/error eg:
 *
 * ```js
 * // pages/page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function ProtectedPage({ customProp }) {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = withPageAuthRequired({
 *   authRequired: false,
 *   async getServerSideProps(ctx) {
 *     const session = getSession(ctx.req, ctx.res);
 *     if (session) {
 *       // user is authenticated
 *     }
 *     return { props: { customProp: 'bar' } };
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type WithPageAuthRequiredOptions<P = any, Q extends ParsedUrlQuery = ParsedUrlQuery> = {
  getServerSideProps?: GetServerSideProps<P, Q>;
  returnTo?: string;
  authRequired?: boolean;
};

/**
 * Wrap your `getServerSideProps` with this method to make sure the user is authenticated before visiting the page.
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
 * If the user visits `/protected-page` without a valid session, it will redirect the user to the login page.
 * Then they will be returned to `/protected-page` after login.
 *
 * @category Server
 */
export type WithPageAuthRequired = {
  <P extends WithPageAuthRequiredProps>(
    Component: ComponentType<P & UserProps>,
    options?: WithPageAuthRequiredCSROptions
  ): React.FC<P>;
  <P, Q extends ParsedUrlQuery = ParsedUrlQuery>(opts?: WithPageAuthRequiredOptions<P, Q>): PageRoute<P, Q>;
};

/**
 * @ignore
 */
export default function withPageAuthRequiredFactory(
  loginUrl: string,
  getSessionCache: () => SessionCache
): WithPageAuthRequired {
  return (
    optsOrComponent: WithPageAuthRequiredOptions | ComponentType<WithPageAuthRequiredProps & UserProps> = {},
    csrOpts?: WithPageAuthRequiredCSROptions
  ): any => {
    if (typeof optsOrComponent === 'function') {
      return withPageAuthRequiredCSR(optsOrComponent, csrOpts);
    }
    const { getServerSideProps, returnTo, authRequired = true } = optsOrComponent;
    return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResultWithSession> => {
      assertCtx(ctx);
      const sessionCache = getSessionCache();
      sessionCache.init(ctx.req, ctx.res, false);
      const session = sessionCache.get(ctx.req, ctx.res);
      if (authRequired && !session?.user) {
        // 10 - redirect
        // 9.5.4 - unstable_redirect
        // 9.4 - res.setHeaders
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
      sessionCache.save(ctx.req, ctx.res);
      if (ret.props instanceof Promise) {
        return { ...ret, props: ret.props.then((props: any) => ({ ...props, user: session?.user })) };
      }
      return { ...ret, props: { ...ret.props, user: session?.user } };
    };
  };
}
