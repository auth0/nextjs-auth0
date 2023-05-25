import { getSession } from '@auth0/nextjs-auth0';

export default async function ServerComponent() {
  const session = await getSession();
  if (session) {
    return <pre>{JSON.stringify(session.user, null, 2)}</pre>;
  }
  return <></>;
}
