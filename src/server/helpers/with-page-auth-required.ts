import { Auth0Client } from "../client.js";
import type {
  AppRouterPageRoute,
  AppRouterPageRouteOpts,
  WithPageAuthRequiredAppRouter,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouter
} from "./types.js";

export type {
  AppRouterPageRoute,
  AppRouterPageRouteOpts,
  GetServerSidePropsResultWithSession,
  PageRoute,
  WithPageAuthRequired,
  WithPageAuthRequiredAppRouter,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouter,
  WithPageAuthRequiredPageRouterOptions
} from "./types.js";

export const appRouteHandlerFactory =
  (
    client: Auth0Client,
    config: {
      loginUrl: string;
    }
  ): WithPageAuthRequiredAppRouter =>
  <P extends AppRouterPageRouteOpts = AppRouterPageRouteOpts>(
    handler: AppRouterPageRoute<P>,
    opts: WithPageAuthRequiredAppRouterOptions<P> = {}
  ) =>
  async (params: P) => {
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
