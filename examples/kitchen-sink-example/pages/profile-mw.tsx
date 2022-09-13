import React from 'react';
import { useUser } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

export default function Profile() {
  const { user, isLoading } = useUser();
  if (isLoading) {
    return <p>Loading...</p>;
  }
  return (
    <Layout>
      <h1>Profile</h1>
      <h4>Profile</h4>
      <pre data-testid="profile">{JSON.stringify(user, null, 2)}</pre>
    </Layout>
  );
}
