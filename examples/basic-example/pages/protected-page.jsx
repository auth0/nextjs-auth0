import React from 'react';
import { useUser, withPageAuthRequired } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

export default function ProtectedPage() {
  const { user, isLoading } = useUser();

  return (
    <Layout>
      <h1>Protected Page</h1>

      {isLoading && <p>Loading profile...</p>}

      {!isLoading && user && (
        <>
          <p>Profile:</p>
          <pre>{JSON.stringify(user, null, 2)}</pre>
        </>
      )}
    </Layout>
  );
}

export const getServerSideProps = withPageAuthRequired();
