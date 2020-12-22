import React from 'react';

// eslint-disable-next-line react/prop-types
export default function protectedPage(): React.ReactElement {
  return <div>Protected Page</div>;
}

export const getServerSideProps = (ctx): any => (global as any).withSSRAuthRequired()(ctx);
