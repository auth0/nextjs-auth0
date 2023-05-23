import React from 'react';
import type { AppProps } from 'next/app';
import { UserProvider } from '@auth0/nextjs-auth0/client';

export default function App({ Component, pageProps }: AppProps): React.ReactElement<AppProps> {
  const { user } = pageProps;

  return (
    <UserProvider user={user} profileUrl="/api/page-router-auth/me" loginUrl="/api/page-router-auth/login">
      <Component {...pageProps} />
    </UserProvider>
  );
}
