'use client';

import { useUser } from '@auth0/nextjs-auth0/client';

export default function ClientComponent() {
  const { user } = useUser();
  if (user) {
    return <pre data-testid="client-component">{JSON.stringify(user, null, 2)}</pre>;
  }
  return <></>;
}
