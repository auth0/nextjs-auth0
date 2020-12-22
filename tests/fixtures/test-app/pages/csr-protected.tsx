import React from 'react';

// eslint-disable-next-line react/prop-types
export default function protectedPage(): React.ReactElement {
  return (global as any).withPageAuthRequiredCSR(() => <div>Protected Page</div>);
}

export const getServerSideProps = (ctx): any => (global as any).withPageAuthRequired()(ctx);
