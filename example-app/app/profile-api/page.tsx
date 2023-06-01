'use client';

import React, { useState, useEffect } from 'react';

export default function ProfileApi() {
  const [user, setUser] = useState();

  useEffect(() => {
    (async () => {
      const res = await fetch(`${window.location.origin}/api/profile`);
      setUser(await res.json());
    })();
  }, []);

  return (
    <main>
      <h1>Profile (fetched from API)</h1>
      <h3>User</h3>
      <pre data-testid="profile-api">{JSON.stringify(user, null, 2)}</pre>
    </main>
  );
}
