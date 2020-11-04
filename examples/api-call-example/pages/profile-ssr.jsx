import React from 'react';
import { withAuth } from '@auth0/nextjs-auth0';

import Layout from '../components/layout';
import LoginRedirect from '../components/login-redirect';
import auth0 from '../lib/auth0';

const Profile = ({ user }) => (
  <Layout>
    <h1>Profile</h1>

    <div>
      <h3>Profile (server rendered)</h3>
      <pre>{JSON.stringify(user, null, 2)}</pre>
    </div>
  </Layout>
);

export default withAuth(Profile, LoginRedirect, auth0);
