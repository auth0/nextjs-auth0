import React from 'react';
import { InferGetServerSidePropsType } from 'next';
import { pageRouterAuth } from '../../lib/auth0';
import Layout from '@/components/layout';

export default function Profile({ user }: InferGetServerSidePropsType<typeof getServerSideProps>): React.ReactElement {
  return (
    <Layout>
      <h1>Profile (server rendered)</h1>
      <pre data-testid="profile">{JSON.stringify(user, null, 2)}</pre>
    </Layout>
  );
}

export const getServerSideProps = pageRouterAuth.withPageAuthRequired();
