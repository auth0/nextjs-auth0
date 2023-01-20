import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { Claims, SessionCache } from '../session';
import { assertCtx } from '../utils/assert';
import { ParsedUrlQuery } from 'querystring';

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
  cts: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResultWithSession<P>>;

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
export type WithPageAuthRequiredOptions<
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
export type WithPageAuthRequired = <
  P extends { [key: string]: any } = { [key: string]: any },
  Q extends ParsedUrlQuery = ParsedUrlQuery
>(
  opts?: WithPageAuthRequiredOptions<P, Q>
) => PageRoute<P, Q>;

/**
 * @ignore
 */
export default function withPageAuthRequiredFactory(
  loginUrl: string,
  getSessionCache: () => SessionCache
): WithPageAuthRequired {
  return ({ getServerSideProps, returnTo } = {}) =>
    async (ctx) => {
      assertCtx(ctx);
      const sessionCache = getSessionCache();
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
}
