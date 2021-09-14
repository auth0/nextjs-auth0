import React from 'react';
import { NextPageContext } from 'next';

// eslint-disable-next-line react/prop-types
export default function protectedPage(): React.ReactElement {
  return (global as any).withPageAuthRequiredCSR(() => <div>Protected Page</div>);
}

export const getServerSideProps = (ctx: NextPageContext): any => (global as any).withPageAuthRequired()(ctx);
