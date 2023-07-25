import React, { useEffect, useState } from 'react';
import { withPageAuthRequired } from '@auth0/nextjs-auth0/client';

import Layout from '@/components/layout';

export default withPageAuthRequired(function ProfileApi() {
  const [user, setUser] = useState();

  useEffect(() => {
    (async () => {
      const res = await fetch(`${window.location.origin}/api/page-router-profile`);
      setUser(await res.json());
    })();
  }, []);

  return (
    <Layout>
      <h1>Profile (fetched from API)</h1>
      <pre data-testid="profile-api">{JSON.stringify(user, null, 2)}</pre>
    </Layout>
  );
});
