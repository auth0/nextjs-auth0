import { getAccessToken, getSession } from '@auth0/nextjs-auth0';

export default async (req, res) => {
  const session = getSession(req, res);
  await getAccessToken(req, res, {
    refresh: true,
    afterRefresh(req, res, session) {
      session.foo = Math.random();
      return session;
    }
  });
  res.json(session);
};
