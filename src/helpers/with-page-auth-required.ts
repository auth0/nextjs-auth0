import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { SessionCache, Session } from '../session';
import { assertCtx } from '../utils/assert';

export type GetServerSidePropsResultWithSession = GetServerSidePropsResult<{
  session?: Session | null;
  [key: string]: any;
}>;

export type PageRoute = (cts: GetServerSidePropsContext) => Promise<GetServerSidePropsResultWithSession>;

export type WithPageAuthRequired = ({}: { getServerSideProps?: GetServerSideProps; loginUrl?: string }) => PageRoute;

export default function withPageAuthRequiredFactory(sessionCache: SessionCache): WithPageAuthRequired {
  return ({ getServerSideProps, loginUrl = '/api/auth/login' } = {}): PageRoute => async (
    ctx
  ): Promise<GetServerSidePropsResultWithSession> => {
    assertCtx(ctx);
    if (!sessionCache.isAuthenticated(ctx.req, ctx.res)) {
      return { unstable_redirect: { destination: `${loginUrl}?returnTo=${ctx.req.url}`, permanent: false } };
    }
    const session = sessionCache.get(ctx.req, ctx.res);
    let ret: GetServerSidePropsResultWithSession = {};
    if (getServerSideProps) {
      ret = await getServerSideProps(ctx);
    }
    return { ...ret, props: { ...(ret.props || {}), user: (session as Session).user } };
  };
}
