import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { get, set, Session, SessionCache } from '../session';

/**
 * Update the session object. The provided `session` object will replace the existing session.
 *
 * **Note** you can't use this method to login or logout - you should use the login and logout handlers for this.
 * If no session is provided, it doesn't contain a user or the user is not authenticated; this is a no-op.
 *
 * **In the App Router:**
 *
 * In a route handler:
 *
 * ```js
 * // app/my-api/route.js
 * import { getSession, updateSession } from '@auth0/nextjs-auth0';
 *
 * export async function GET() {
 *   const { user } = await getSession();
 *   await updateSession({ ...session, user: { ...session.user, foo: 'bar' }});
 *   return NextResponse.json({ foo: 'bar' });
 * }
 *
 * // Or, it's slightly more efficient to use the `req`, `res` args if you're
 * // using another part of the SDK like `withApiAuthRequired` or `getSession`.
 * import { getSession, updateSession, withApiAuthRequired } from '@auth0/nextjs-auth0';
 *
 * const GET = withApiAuthRequired(async function GET(req) {
 *   const res = new NextResponse();
 *   const { user } = await getSession(req, res);
 *   await updateSession(req, res, { ...session, user: { ...session.user, foo: 'bar' }});
 *   return NextResponse.json({ foo: 'bar' }, res);
 * });
 *
 * export { GET };
 * ```
 *
 * In a Server Action in a page or React Server Component:
 *
 * ```js
 * // app/my-page/page.js
 * import { getSession, updateSession } from '@auth0/nextjs-auth0';
 *
 * export default async function Page() {
 *   async function updateUser(updates) {
 *     'use server';
 *     const { user } = await getSession();
 *     await updateSession(req, res, { ...session, user: { ...session.user, ...updates }});
 *   }
 *   return (
 *     <form action={updateUser}>
 *       <button type="submit">Update User</button>
 *     </form>
 *   );
 * }
 * ```
 *
 * **Note:** You can't write to the cookie in a React Server Component, so updates
 * to the session would need to happen in a Server Action.
 * More info on Server Actions https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions
 *
 * You can also update the session in a page or route in the Edge Runtime:
 *
 * ```js
 * // app/my-page/page.js
 * import { getSession, updateSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export default async function Page() {
 *   async function updateUser(updates) {
 *     'use server';
 *     const { user } = await getSession();
 *     await updateSession(req, res, { ...session, user: { ...session.user, ...updates }});
 *   }
 *   return (
 *     <form action={updateUser}>
 *       <button type="submit">Update User</button>
 *     </form>
 *   );
 * }
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
 * import { getSession, updateSession } from '@auth0/nextjs-auth0';
 *
 * export default async function MyApi(req, res) {
 *   const { user } = await getSession(req, res);
 *   await updateSession(req, res, { ...session, user: { ...session.user, foo: 'bar' }});
 *   res.status(200).json({ name: user.name });
 * }
 * ```
 *
 * In a page:
 *
 * ```js
 * // pages/my-page.js
 * import { getSession, updateSession } from '@auth0/nextjs-auth0';
 *
 * export default function About() {
 *   return <div>About</div>;
 * }
 *
 * export async function getServerSideProps(ctx) {
 *   const { user } = await getSession(ctx.req, ctx.res);
 *   await updateSession(req, res, { ...session, user: { ...session.user, foo: 'bar' }});
 *   return { props: { foo: 'bar' } };
 * }
 * ```
 *
 * **In middleware:**
 *
 * ```js
 * import { NextResponse } from 'next/server';
 * import { getSession, updateSession } from '@auth0/nextjs-auth0/edge'; // Note the /edge import
 *
 * export async function middleware(req) {
 *   const res = new NextResponse();
 *   const { user } = await getSession(req, res);
 *   await updateSession(req, res, { ...session, user: { ...session.user, foo: 'bar' }});
 *   return NextResponse.redirect(new URL('/bar', request.url), res);
 * }
 *
 * // See "Matching Paths" below to learn more
 * export const config = {
 *   matcher: '/foo',
 * };
 *
 * @category Server
 */
export type UpdateSession = (
  ...args:
    | [IncomingMessage, ServerResponse, Session]
    | [NextApiRequest, NextApiResponse, Session]
    | [NextRequest, NextResponse, Session]
    | [Session]
) => Promise<void>;

/**
 * @ignore
 */
export default function updateSessionFactory(sessionCache: SessionCache): UpdateSession {
  return async (reqOrSession, res?, newSession?) => {
    const session = (res ? newSession : reqOrSession) as Session | undefined;
    const req = (res ? reqOrSession : undefined) as IncomingMessage | NextApiRequest | NextRequest | undefined;

    const [prevSession, iat] = await get({ sessionCache, req, res });
    if (!prevSession || !session || !session.user) {
      return;
    }
    await set({ req, res, session, sessionCache, iat });
  };
}
