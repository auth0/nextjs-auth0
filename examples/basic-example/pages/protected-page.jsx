import React from 'react';
import { useUser, withPageAuthRequired } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

function ProtectedPage(props) {
  // props.data === 'foo
  const { user, error, isLoading } = useUser();

  return (
    <Layout>
      <h1>Protected Page {props.data}</h1>

      {isLoading && <p>Loading profile...</p>}

      {error && (
        <>
          <h4>Error</h4>
          <pre>{error.message}</pre>
        </>
      )}

      {user && (
        <>
          <h4>Profile</h4>
          <pre>{JSON.stringify(user, null, 2)}</pre>
        </>
      )}
    </Layout>
  );
}

export default withPageAuthRequired(ProtectedPage);

export async function getServerSideProps(context) {
  const websiteData = await Promise.resolve('foo');

  return {
    props: { data: websiteData }
  };
}
