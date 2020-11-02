import React from 'react';
import { useUser } from '@auth0/nextjs-auth0';

import useApi from '../lib/use-api';
import Layout from '../components/layout';

export default function TvShows() {
  const { user, loading } = useUser();
  const { response, error, isLoading } = useApi('/api/shows');

  return (
    <Layout user={user} loading={loading}>
      <h1>TV Shows</h1>

      {isLoading && <p>Loading TV shows...</p>}

      {!isLoading && response && (
        <>
          <p>My favourite TV shows:</p>
          <pre>
            {JSON.stringify(
              response.shows.map((s) => s.show.name),
              null,
              2
            )}
          </pre>
        </>
      )}

      {!isLoading && error && (
        <>
          <p>Error loading TV shows</p>
          <pre style={{ color: 'red' }}>{JSON.stringify(error, null, 2)}</pre>
        </>
      )}
    </Layout>
  );
}
