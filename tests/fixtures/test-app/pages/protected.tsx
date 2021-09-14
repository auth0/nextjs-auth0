import React from 'react';
import { NextPageContext } from 'next';

export default function protectedPage(): React.ReactElement {
  return <div>Protected Page</div>;
}

export const getServerSideProps = (ctx: NextPageContext): any => (global as any).withPageAuthRequired()(ctx);
