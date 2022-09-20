import React from 'react';
import { NextPageContext } from 'next';

export default function protectedPage({ user }: { user?: { sub: string } }): React.ReactElement {
  return <div>Protected Page {user ? user.sub : ''}</div>;
}

export const getServerSideProps = (ctx: NextPageContext): any => global.withPageAuthRequired()(ctx);
