import { getSession, getAccessToken } from '@auth0/nextjs-auth0';

export default async function ServerComponent() {
  const session = await getSession();
  const accessToken = await getAccessToken();
  if (session) {
    return (
      <>
        <h3>Access Token</h3>
        <pre data-testid="server-component-at">{JSON.stringify(accessToken, null, 2)}</pre>
        <h3>User</h3>
        <pre data-testid="server-component">{JSON.stringify(session.user, null, 2)}</pre>
      </>
    );
  }
  return <></>;
}
