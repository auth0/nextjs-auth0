import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { SessionCache, Session } from '../session';
import { assertCtx } from '../utils/assert';

export type GetServerSidePropsResultWithSession = GetServerSidePropsResult<{
  session?: Session | null;
  [key: string]: any;
}>;

export type PageRoute = (cts: GetServerSidePropsContext) => Promise<GetServerSidePropsResultWithSession>;

export type WithPageAuthRequired = (fn?: GetServerSideProps, authRequired?: boolean) => PageRoute;

export default function withPageAuthFactory(sessionCache: SessionCache): WithPageAuthRequired {
  return (fn?: GetServerSideProps): PageRoute => async (ctx): Promise<GetServerSidePropsResultWithSession> => {
    assertCtx(ctx);
    if (!sessionCache.isAuthenticated(ctx.req, ctx.res)) {
      return { unstable_redirect: { destination: `/api/auth/login?returnTo=${ctx.req.url}`, permanent: false } };
    }
    const session = sessionCache.get(ctx.req, ctx.res);
    let ret: GetServerSidePropsResultWithSession = {};
    if (fn) {
      ret = await fn(ctx);
    }
    return { ...ret, props: { ...(ret.props || {}), user: (session as Session).user } };
  };
}
