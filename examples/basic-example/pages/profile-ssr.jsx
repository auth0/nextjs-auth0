import React from 'react';

import Layout from '../components/layout';
import withAuth from '../components/with-auth';

const Profile = ({ user }) => (
  <Layout>
    <h1>Profile</h1>

    <div>
      <h3>Profile (server rendered)</h3>
      <pre id="profile">{JSON.stringify(user, null, 2)}</pre>
    </div>
  </Layout>
);

export default withAuth(Profile);
