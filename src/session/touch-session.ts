import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { get, set, SessionCache } from '../session';

/**
 * Touch the session object. If rolling sessions are enabled and autoSave is disabled, you will need
 * to call this method to update the session expiry.
 *
 * **In the App Router:**
 *
 * In a route handler:
 *
 * ```js
 * // app/my-api/route.js
 * import { touchSession } from '@auth0/nextjs-auth0';
 *
 * export async function GET() {
 *   await touchSession();
 *   return NextResponse.json({ foo: 'bar' });
 * }
 *
 * // Or, it's slightly more efficient to use the `req`, `res` args if you're
 * // using another part of the SDK like `withApiAuthRequired` or `getSession`.
 * import { touchSession, withApiAuthRequired } from '@auth0/nextjs-auth0';
 *
 * const GET = withApiAuthRequired(async function GET(req) {
 *   const res = new NextResponse();
 *   await touchSession(req, res);
 *   return NextResponse.json({ foo: 'bar' }, res);
 * });
 *
 * export { GET };
 * ```
 *
 * In a page or React Server Component:
 *
 * ```js
 * // app/my-page/page.js
 * import { touchSession } from '@auth0/nextjs-auth0';
 *
 * export default async function MyPage({ params, searchParams }) {
 *   await touchSession();
 *   return <h1>My Page</h1>;
 * }
 * ```
 *
 * **Note:** You can't write to the cookie in a React Server Component, so updates
 * to the session like setting the expiry of the rolling session won't be persisted.
 * For this, we recommend interacting with the session in the middleware.
 *
 * You can also touch the session in a page or route in the Edge Runtime:
 *
 * ```js
 * // app/my-api/route.js
 * import { getSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export default async function MyPage({ params, searchParams }) {
 *   await touchSession();
 *   return <h1>My Page</h1>;
 * }
 *
 * export const runtime = 'edge';
 * ```
 *
 * **Note:** The Edge runtime features are only supported in the App Router.
 *
 * **In the Page Router:**
 *
 * In an API handler:
 *
 * ```js
 * // pages/api/my-api.js
 * import { touchSession } from '@auth0/nextjs-auth0';
 *
 * export default async function MyApi(req, res) {
 *   await touchSession(req, res);
 *   res.status(200).json({ name: user.name });
 * }
 * ```
 *
 * In a page:
 *
 * ```js
 * // pages/my-page.js
 * import { touchSession } from '@auth0/nextjs-auth0';
 *
 * export default function About() {
 *   return <div>About</div>;
 * }
 *
 * export async function getServerSideProps(ctx) {
 *   await touchSession(ctx.req, ctx.res);
 *   return { props: { foo: 'bar' } };
 * }
 * ```
 *
 * **In middleware:**
 *
 * ```js
 * import { NextResponse } from 'next/server';
 * import { touchSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export async function middleware(req) {
 *   const res = new NextResponse();
 *   await touchSession(req, res);
 *   return NextResponse.redirect(new URL('/bar', request.url), res);
 * }
 *
 * export const config = {
 *   matcher: '/foo',
 * };
 *
 * @category Server
 */
export type TouchSession = (
  ...args: [IncomingMessage, ServerResponse] | [NextApiRequest, NextApiResponse] | [NextRequest, NextResponse] | []
) => Promise<void>;

/**
 * @ignore
 */
export default function touchSessionFactory(sessionCache: SessionCache): TouchSession {
  return async (req?, res?) => {
    const [session, iat] = await get({ sessionCache, req, res });
    if (!session) {
      return;
    }
    await set({ req, res, session, sessionCache, iat });
  };
}
