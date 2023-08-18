import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { SessionCache, Session, get } from '../session';

/**
 * Get the user's session from the server.
 *
 * **In the App Router:**
 *
 * In a route handler:
 *
 * ```js
 * // app/my-api/route.js
 * import { getSession } from '@auth0/nextjs-auth0';
 *
 * export async function GET() {
 *   const { user } = await getSession();
 *   return NextResponse.json({ foo: 'bar' });
 * }
 *
 * // Or, it's slightly more efficient to use the `req`, `res` args if you're
 * // using another part of the SDK like `withApiAuthRequired` or `getAccessToken`.
 * import { getSession, withApiAuthRequired } from '@auth0/nextjs-auth0';
 *
 * const GET = withApiAuthRequired(async function GET(req) {
 *   const res = new NextResponse();
 *   const { user } = await getSession(req, res);
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
 * import { getSession } from '@auth0/nextjs-auth0';
 *
 * export default async function MyPage({ params, searchParams }) {
 *   const { user } = await getSession();
 *   return <h1>My Page</h1>;
 * }
 * ```
 *
 * **Note:** You can't write to the cookie in a React Server Component, so updates
 * to the session like setting the expiry of the rolling session won't be persisted.
 * For this, we recommend interacting with the session in the middleware.
 *
 * You can also get the session in a page or route in the Edge Runtime:
 *
 * ```js
 * // app/my-api/route.js
 * import { getSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export default async function MyPage({ params, searchParams }) {
 *   const { user } = await getSession();
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
 * import { getSession } from '@auth0/nextjs-auth0';
 *
 * export default async function MyApi(req, res) {
 *   const { user } = await getSession(req, res);
 *   res.status(200).json({ name: user.name });
 * }
 * ```
 *
 * In a page:
 *
 * ```js
 * // pages/my-page.js
 * import { getSession } from '@auth0/nextjs-auth0';
 *
 * export default function About() {
 *   return <div>About</div>;
 * }
 *
 * export async function getServerSideProps(ctx) {
 *   const { user } = await getSession(ctx.req, ctx.res);
 *   return { props: { foo: 'bar' } };
 * }
 * ```
 *
 * **In middleware:**
 *
 * ```js
 * import { NextResponse } from 'next/server';
 * import { getSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export async function middleware(req) {
 *   const res = new NextResponse();
 *   const { user } = await getSession(req, res);
 *   return NextResponse.redirect(new URL('/bar', request.url), res);
 * }
 *
 * export const config = {
 *   matcher: '/foo',
 * };
 *
 * @category Server
 */
export type GetSession = (
  ...args: [IncomingMessage, ServerResponse] | [NextApiRequest, NextApiResponse] | [NextRequest, NextResponse] | []
) => Promise<Session | null | undefined>;

/**
 * @ignore
 */
export default function sessionFactory(sessionCache: SessionCache): GetSession {
  return async (req?, res?) => {
    const [session] = await get({ req, res, sessionCache });
    return session;
  };
}
