import React from 'react';
import { NextPageContext } from 'next';

export default function wrappedGetServerSidePropsPage({
  isAuthenticated
}: {
  isAuthenticated?: boolean;
}): React.ReactElement {
  return <div>isAuthenticated: {String(isAuthenticated)}</div>;
}

export const getServerSideProps = (_ctx: NextPageContext): any =>
  (global as any).getServerSidePropsWrapper(async (ctx: NextPageContext) => {
    const session = (global as any).getSession(ctx.req, ctx.res);
    const asyncProps = (global as any).asyncProps;
    const props = { isAuthenticated: !!session };
    return { props: asyncProps ? Promise.resolve(props) : props };
  })(_ctx);
