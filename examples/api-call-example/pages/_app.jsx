import React from 'react';
import { UserProvider } from '@auth0/nextjs-auth0';

export default function App({ Component, pageProps }) {
  // If you've used `withSSRAuthRequired`, pageProps.user can pre-populate the hook
  // if you haven't used `withSSRAuthRequired`, pageProps.user is undefined so the hook
  // fetches the user from the API routes
  const { user } = pageProps;

  return (
    <UserProvider user={user} profileUrl="/api/me">
      <Component {...pageProps} />
    </UserProvider>
  );
}
