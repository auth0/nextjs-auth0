import type { ParsedUrlQuery } from "querystring";
import {
  GetServerSideProps,
  GetServerSidePropsContext,
  GetServerSidePropsResult
} from "next";

import { User } from "../../types/index.js";
import { Auth0Client } from "../client.js";

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
 * Returns unknown to avoid React dependency while maintaining type safety.
 */
export type AppRouterPageRoute = (
  obj: AppRouterPageRouteOpts
) => Promise<unknown>;

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
 */
export type WithPageAuthRequiredAppRouterOptions = {
  returnTo?:
    | string
    | ((obj: AppRouterPageRouteOpts) => Promise<string> | string);
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
export type WithPageAuthRequiredAppRouter = (
  fn: AppRouterPageRoute,
  opts?: WithPageAuthRequiredAppRouterOptions
) => AppRouterPageRoute;

/**
 * Protects Page router pages {@link WithPageAuthRequiredPageRouter} or
 * App router pages {@link WithPageAuthRequiredAppRouter}
 */
export type WithPageAuthRequired = WithPageAuthRequiredPageRouter &
  WithPageAuthRequiredAppRouter;

export const appRouteHandlerFactory =
  (
    client: Auth0Client,
    config: {
      loginUrl: string;
    }
  ): WithPageAuthRequiredAppRouter =>
  (handler, opts = {}) =>
  async (params) => {
    const session = await client.getSession();

    if (!session?.user) {
      const returnTo =
        typeof opts.returnTo === "function"
          ? await opts.returnTo(params)
          : opts.returnTo;
      const { redirect } = await import("next/navigation.js");
      redirect(
        `${config.loginUrl}${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ""}`
      );
    }
    return handler(params);
  };

export const pageRouteHandlerFactory =
  (
    client: Auth0Client,
    config: {
      loginUrl: string;
    }
  ): WithPageAuthRequiredPageRouter =>
  ({ getServerSideProps, returnTo } = {}) =>
  async (ctx) => {
    const session = await client.getSession(ctx.req);

    if (!session?.user) {
      return {
        redirect: {
          destination: `${config.loginUrl}?returnTo=${encodeURIComponent(returnTo || ctx.resolvedUrl)}`,
          permanent: false
        }
      };
    }
    let ret: any = { props: {} };
    if (getServerSideProps) {
      ret = await getServerSideProps(ctx);
    }
    if (ret.props instanceof Promise) {
      const props = await ret.props;
      return {
        ...ret,
        props: {
          user: session.user,
          ...props
        }
      };
    }
    return { ...ret, props: { user: session.user, ...ret.props } };
  };
