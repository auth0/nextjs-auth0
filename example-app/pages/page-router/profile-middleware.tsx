import React from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';

import Layout from '@/components/layout';

export default function Profile() {
  const { user, isLoading } = useUser();
  if (isLoading) {
    return <p>Loading...</p>;
  }
  return (
    <Layout>
      <h1>Profile (client rendered / protected by Middleware)</h1>
      <pre data-testid="profile">{JSON.stringify(user, null, 2)}</pre>
    </Layout>
  );
}
