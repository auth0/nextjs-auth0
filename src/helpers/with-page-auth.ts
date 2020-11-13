import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { SessionCache, Session } from '../session';

export type GetServerSidePropsResultWithSession = GetServerSidePropsResult<{
  session?: Session | null;
  [key: string]: any;
}>;

export type PageRoute = (cts: GetServerSidePropsContext) => Promise<GetServerSidePropsResultWithSession>;

export type WithPageAuth = (fn?: GetServerSideProps, authRequired?: boolean) => PageRoute;

export default function withPageAuthFactory(sessionCache: SessionCache): WithPageAuth {
  return (fn?: GetServerSideProps, authRequired?: boolean): PageRoute => async (
    ctx
  ): Promise<GetServerSidePropsResultWithSession> => {
    if (authRequired && !sessionCache.isAuthenticated(ctx.req, ctx.res)) {
      return { unstable_redirect: { destination: '/api/login', permanent: false } };
    }
    const session = sessionCache.get(ctx.req, ctx.res);
    let ret: GetServerSidePropsResultWithSession = {};
    if (fn) {
      ret = await fn(ctx);
    }
    return { ...ret, props: { session, ...(ret.props || {}) } };
  };
}
