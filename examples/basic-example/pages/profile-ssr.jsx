import React from 'react';

import auth0 from '../lib/auth0';
import { fetchUser } from '../lib/user';
import Layout from '../components/layout';
import withAuth from '../components/with-auth';

const Profile = ({ user }) => (
  <Layout user={user}>
    <h1>Profile</h1>

    <div>
      <h3>Profile (server rendered)</h3>
      <pre>{JSON.stringify(user, null, 2)}</pre>
    </div>
  </Layout>
);

export default withAuth(Profile);
