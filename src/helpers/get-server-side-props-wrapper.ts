import { GetServerSideProps } from 'next';
import { ParsedUrlQuery } from 'querystring';
import SessionCache from '../session/cache';

/**
 * If you're using >=Next 12 and {@link getSession} or {@link getAccessToken} without `withPageAuthRequired`, because
 * you don't want to require authentication on your route, you might get a warning/error: "You should not access 'res'
 * after getServerSideProps resolves". You can work around this by wrapping your `getServerSideProps` in
 * `getServerSidePropsWrapper`, this ensures that the code that accesses `res` will run within
 * the lifecycle of `getServerSideProps`, avoiding the warning/error eg:
 *
 * **NOTE: you do not need to do this if you're already using {@link WithPageAuthRequired}**
 *
 * ```js
 * // pages/protected-page.js
 * import { withPageAuthRequired } from '@auth0/nextjs-auth0';
 *
 * export default function ProtectedPage() {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = getServerSidePropsWrapper(async (ctx) => {
 *   const session = getSession(ctx.req, ctx.res);
 *   if (session) {
 *     // Use is authenticated
 *   } else {
 *     // User is not authenticated
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type GetServerSidePropsWrapper<P = any, Q extends ParsedUrlQuery = ParsedUrlQuery> = (
  getServerSideProps: GetServerSideProps<P, Q>
) => GetServerSideProps<P, Q>;

/**
 * @ignore
 */
export default function getServerSidePropsWrapperFactory(getSessionCache: () => SessionCache) {
  return function getServerSidePropsWrapper(getServerSideProps: GetServerSideProps): GetServerSideProps {
    return async function wrappedGetServerSideProps(...args) {
      const sessionCache = getSessionCache();
      const [ctx] = args;
      sessionCache.init(ctx.req, ctx.res, false);
      const ret = await getServerSideProps(...args);
      sessionCache.save(ctx.req, ctx.res);
      return ret;
    };
  };
}
