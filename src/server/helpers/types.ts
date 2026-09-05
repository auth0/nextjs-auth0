import type { ParsedUrlQuery } from "querystring";
import type {
  GetServerSideProps,
  GetServerSidePropsContext,
  GetServerSidePropsResult,
  NextApiHandler
} from "next";
import type { NextRequest } from "next/server.js";

import type { User } from "../../types/index.js";

/**
 * This contains `param`s, which is a Promise that resolves to an object
 * containing the dynamic route parameters for the current route.
 *
 * See https://nextjs.org/docs/app/api-reference/file-conventions/route#context-optional
 */
export type AppRouteHandlerFnContext = {
  params?: Promise<Record<string, string | string[]>>;
};

/**
 * Handler function for app directory api routes.
 *
 * See: https://nextjs.org/docs/app/api-reference/file-conventions/route
 */
export type AppRouteHandlerFn = (
  /**
   * Incoming request object.
   */
  req: NextRequest | Request,
  /**
   * Context properties on the request (including the parameters if this was a
   * dynamic route).
   */
  ctx: AppRouteHandlerFnContext
) => Promise<Response> | Response;

/**
 * Wrap an app router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // app/protected-api/route.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default auth0.withApiAuthRequired(function Protected(req) {
 *   const session = auth0.getSession(req);
 *   ...
 * });
 * ```
 *
 * If you visit `/protected-api` without a valid session cookie, you will get a 401 response.
 */
export type WithApiAuthRequiredAppRoute = (
  apiRoute: AppRouteHandlerFn
) => AppRouteHandlerFn;

/**
 * Wrap a page router API route to check that the user has a valid session. If they're not logged in the
 * handler will return a 401 Unauthorized.
 *
 * ```js
 * // pages/api/protected-route.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default auth0.withApiAuthRequired(function ProtectedRoute(req, res) {
 *   const session = auth0.getSession(req);
 *   ...
 * });
 * ```
 *
 * If you visit `/api/protected-route` without a valid session cookie, you will get a 401 response.
 */
export type WithApiAuthRequiredPageRoute = (
  apiRoute: NextApiHandler
) => NextApiHandler;

/**
 * Protects API routes for Page router pages {@link WithApiAuthRequiredPageRoute} or
 * App router pages {@link WithApiAuthRequiredAppRoute}
 */
export type WithApiAuthRequired = WithApiAuthRequiredAppRoute &
  WithApiAuthRequiredPageRoute;

/**
 * If you wrap your `getServerSideProps` with {@link WithPageAuthRequired} your props object will be augmented with
 * the user property, which will be the {@link User} object.
 *
 * ```js
 * // pages/profile.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default function Profile({ user }) {
 *   return <div>Hello {user.name}</div>;
 * }
 *
 * export const getServerSideProps = auth0.withPageAuthRequired();
 * ```
 */
export type GetServerSidePropsResultWithSession<P = any> =
  GetServerSidePropsResult<P & { user: User }>;

/**
 * A page route that has been augmented with {@link WithPageAuthRequired}.
 */
export type PageRoute<P, Q extends ParsedUrlQuery = ParsedUrlQuery> = (
  ctx: GetServerSidePropsContext<Q>
) => Promise<GetServerSidePropsResultWithSession<P>>;

/**
 * Objects containing the route parameters and search parameters of the page.
 */
export type AppRouterPageRouteOpts = {
  params?: Promise<Record<string, string | string[]>>;
  searchParams?: Promise<{ [key: string]: string | string[] | undefined }>;
};

/**
 * An app route that has been augmented with {@link WithPageAuthRequired}.
 * Returns any to be compatible with React's return types while avoiding React dependency.
 *
 * The generic parameter `P` allows passing Next.js `PageProps` or `LayoutProps`
 * types for strongly-typed route parameters:
 *
 * ```ts
 * export default auth0.withPageAuthRequired(
 *   async function Page(props: PageProps<"/customers/[id]/details">) {
 *     const { id } = await props.params;
 *     return <div>{id}</div>;
 *   }
 * );
 * ```
 */
export type AppRouterPageRoute<
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
> = (obj: P) => Promise<any>;

/**
 * If you have a custom returnTo url you should specify it in `returnTo`.
 *
 * You can pass in your own `getServerSideProps` method, the props returned from this will be
 * merged with the user props. You can also access the user session data by calling `getSession`
 * inside of this method. For example:
 *
 * ```js
 * // pages/protected-page.js
 * import { auth0 } from "@/lib/auth0";
 *
 * export default function ProtectedPage({ user, customProp }) {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = auth0.withPageAuthRequired({
 *   // returnTo: '/unauthorized',
 *   async getServerSideProps(ctx) {
 *     // access the user session if needed
 *     // const session = await auth0.getSession(ctx.req);
 *     return {
 *       props: {
 *         // customProp: 'bar',
 *       }
 *     };
 *   }
 * });
 * ```
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
 * import { auth0 } from "@/lib/auth0";
 *
 * export default function ProtectedPage() {
 *   return <div>Protected content</div>;
 * }
 *
 * export const getServerSideProps = auth0.withPageAuthRequired();
 * ```
 *
 * If the user visits `/protected-page` without a valid session, it will redirect the user to the
 * login page. Then they will be returned to `/protected-page` after login.
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
 * * @template P The type of the page or layout props, extending {@link AppRouterPageRouteOpts}.
 * This allows the `returnTo` callback to access strongly-typed route parameters.
 */
export type WithPageAuthRequiredAppRouterOptions<
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
> = {
  /**
   * The URL to redirect the user to after a successful login.
   * * Can be a static string or a function that receives the page props.
   * When used as a function, the generic `P` ensures that `params` and `searchParams`
   * match the specific types of your route (e.g., from Next.js `PageProps`).
   */
  returnTo?: string | ((obj: P) => Promise<string> | string);
};

/**
 * Wrap your Server Component with this method to make sure the user is authenticated before
 * visiting the page.
 *
 * ```js
 * // app/protected-page/page.js
 * import { auth0 } from "@/lib/auth0";
 *
 * const ProtectedPage = auth0.withPageAuthRequired(async function ProtectedPage() {
 *   return <div>Protected content</div>;
 * }, { returnTo: '/protected-page' });
 *
 * export default ProtectedPage;
 * ```
 *
 * If the user visits `/protected-page` without a valid session, it will redirect the user to the
 * login page.
 *
 * Note: Server Components are not aware of the req or the url of the page. So if you want the user to return to the
 * page after login, you must specify the `returnTo` option.
 *
 * You can specify a function to `returnTo` that accepts the `params` (A Promise that resolves to
 * an object containing the dynamic route parameters) and `searchParams` (A Promise that resolves to an
 * object containing the search parameters of the current URL)
 * argument from the page, to preserve dynamic routes and search params.
 *
 * ```js
 * // app/protected-page/[slug]/page.js
 * import { AppRouterPageRouteOpts } from '@auth0/nextjs-auth0/server';
 * import { auth0 } from "@/lib/auth0";
 *
 * const ProtectedPage = auth0.withPageAuthRequired(async function ProtectedPage({
 *   params, searchParams
 * }: AppRouterPageRouteOpts) {
 *   const slug = (await params)?.slug as string;
 *   return <div>Protected content for {slug}</div>;
 * }, {
 *   returnTo({ params }) {
 *     return `/protected-page/${(await params)?.slug}`;
 *   }
 * });
 *
 * export default ProtectedPage;
 * ```
 */
export type WithPageAuthRequiredAppRouter = <
  P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts
>(
  fn: AppRouterPageRoute<P>,
  opts?: WithPageAuthRequiredAppRouterOptions<P>
) => AppRouterPageRoute<P>;

/**
 * Protects Page router pages {@link WithPageAuthRequiredPageRouter} or
 * App router pages {@link WithPageAuthRequiredAppRouter}
 */
export type WithPageAuthRequired = WithPageAuthRequiredPageRouter &
  WithPageAuthRequiredAppRouter;
