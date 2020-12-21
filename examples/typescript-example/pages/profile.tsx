import React from 'react';
import { useUser, withCSRAuthRequired } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

export default withCSRAuthRequired(function Profile() {
  const { user, loading } = useUser();

  return (
    <Layout>
      <h1>Profile</h1>

      {loading && <p>Loading profile...</p>}

      {!loading && user && (
        <>
          <p>Profile:</p>
          <pre id="profile">{JSON.stringify(user, null, 2)}</pre>
        </>
      )}
    </Layout>
  );
});
