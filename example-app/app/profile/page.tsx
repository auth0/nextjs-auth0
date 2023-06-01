import React from 'react';
import { getSession, withPageAuthRequired } from '@auth0/nextjs-auth0';
import ServerComponent from '@/app/server-component';
import ClientComponent from '@/app/client-component';

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
        <pre>{JSON.stringify(session?.user, null, 2)}</pre>
        <h2>Server Component:</h2>
        {/*@ts-expect-error Async Server Component*/}
        <ServerComponent />
        <h2>Client Component:</h2>
        <ClientComponent />
      </main>
    );
  },
  { returnTo: '/profile' }
);
