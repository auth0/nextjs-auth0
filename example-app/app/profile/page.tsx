import React from 'react';
import ServerComponent from '@/app/profile/server-component';
import ClientComponent from '@/app/profile/client-component';

export default function Page() {
  return (
    <main>
      <h1>Profile</h1>
      <h2>Server Component:</h2>
      {/*@ts-expect-error Async Server Component*/}
      <ServerComponent />
      <h2>Client Component:</h2>
      <ClientComponent />
    </main>
  );
}
