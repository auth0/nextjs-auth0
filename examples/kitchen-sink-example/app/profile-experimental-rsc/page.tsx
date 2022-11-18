import { headers } from 'next/headers';
import { getSession as auth0GetSession } from '@auth0/nextjs-auth0';
import { IncomingMessage, ServerResponse } from 'http';
import { Socket } from 'net';

// Note: This is an experiment to test that the SDK works in the experimental app directory.
// You should not rely on this code (or the app directory) in production.
const reqRes = () => {
  const req = new IncomingMessage(new Socket());
  headers().forEach((v, k) => {
    req.headers[k] = v;
  });
  const res = new ServerResponse(req);
  return { req, res };
};

export function getSession() {
  const { req, res } = reqRes();
  return auth0GetSession(req, res);
}

export default async function ExperimentalRscPage() {
  const session = await getSession();
  return (
    <div>
      <h1>Profile</h1>
      <h4>Profile</h4>
      <pre>{JSON.stringify(session || {}, null, 2)}</pre>
    </div>
  );
}
