import React from 'react';
import { useUser, withPageAuthRequired } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

export default withPageAuthRequired(function Profile(): React.ReactElement {
  const { user, isLoading } = useUser();

  return (
    <Layout>
      <h1>Profile</h1>

      {isLoading && <p>Loading profile...</p>}

      {!isLoading && user && (
        <>
          <p>Profile:</p>
          <pre id="profile">{JSON.stringify(user, null, 2)}</pre>
        </>
      )}
    </Layout>
  );
});
