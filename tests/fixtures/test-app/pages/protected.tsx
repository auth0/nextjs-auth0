import React from 'react';
import { NextPageContext } from 'next';

export default function protectedPage({ user }): React.ReactElement {
  return <div>Protected Page {user ? user.sub : ''}</div>;
}

export const getServerSideProps = (ctx: NextPageContext): any => (global as any).withPageAuthRequired()(ctx);
