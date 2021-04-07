import { getAccessToken } from '@auth0/nextjs-auth0';

export default async function (req, res) {
  let accessToken;

  try {
    const tokenPayload = await getAccessToken(req, res, { refresh: true });
    accessToken = tokenPayload.accessToken;
  } catch (err) {
    console.error(error);
  }

  console.log('AT:', accessToken);

  res.json({ ok: true });
}
