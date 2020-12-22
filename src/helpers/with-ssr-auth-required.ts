import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { SessionCache, Session, Claims } from '../session';
import { assertCtx } from '../utils/assert';

export type GetServerSidePropsResultWithSession = GetServerSidePropsResult<{
  user?: Claims | null;
  [key: string]: any;
}>;

export type PageRoute = (cts: GetServerSidePropsContext) => Promise<GetServerSidePropsResultWithSession>;

export type WithSSRAuthRequiredOptions = { getServerSideProps?: GetServerSideProps; loginUrl?: string };

export type WithSSRAuthRequired = (opts?: WithSSRAuthRequiredOptions) => PageRoute;

export default function withSSRAuthRequiredFactory(sessionCache: SessionCache): WithSSRAuthRequired {
  return ({ getServerSideProps, loginUrl = '/api/auth/login' } = {}): PageRoute => async (
    ctx
  ): Promise<GetServerSidePropsResultWithSession> => {
    assertCtx(ctx);
    if (!sessionCache.isAuthenticated(ctx.req, ctx.res)) {
      // 10 - redirect
      // 9.5.4 - unstable_redirect
      // 9.4 - res.setHeaders
      return { redirect: { destination: `${loginUrl}?returnTo=${ctx.resolvedUrl}`, permanent: false } };
    }
    const session = sessionCache.get(ctx.req, ctx.res) as Session;
    let ret: any = { props: {} };
    if (getServerSideProps) {
      ret = await getServerSideProps(ctx);
    }
    return { ...ret, props: { ...ret.props, user: session.user } };
  };
}
