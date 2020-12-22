import React from 'react';
import { UserProfile, withSSRAuthRequired } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';

type ProfileProps = { user: UserProfile };

export default function Profile({ user }: ProfileProps): React.ReactElement {
  return (
    <Layout>
      <h1>Profile</h1>

      <div>
        <h3>Profile (server rendered)</h3>
        <pre id="profile">{JSON.stringify(user, null, 2)}</pre>
      </div>
    </Layout>
  );
}

export const getServerSideProps = withSSRAuthRequired();
