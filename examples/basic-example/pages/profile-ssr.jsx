import React from 'react';
import { withPageAuthRequired } from '@auth0/nextjs-auth0';
import Layout from '../components/layout';

const Profile = ({ user }) => (
  <Layout>
    <h1>Profile</h1>

    <div>
      <h3>Profile (server rendered)</h3>
      <pre id="profile">{JSON.stringify(user, null, 2)}</pre>
    </div>
  </Layout>
);

export default Profile;

export const getServerSideProps = withPageAuthRequired();
