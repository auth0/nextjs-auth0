import React from 'react';
import { getSession, withPageAuthRequired } from '@auth0/nextjs-auth0/edge';

export default withPageAuthRequired(
  async function Page() {
    const session = await getSession();

    return (
      <main>
        <h1>Profile</h1>
        <h2>Page:</h2>
        <h3>Access Token</h3>
        <pre>{JSON.stringify({ accessToken: session?.accessToken }, null, 2)}</pre>
        <h3>User</h3>
        <pre data-testid="profile">{JSON.stringify(session?.user, null, 2)}</pre>
      </main>
    );
  },
  { returnTo: '/edge-profile' }
);

export const runtime = 'edge';
