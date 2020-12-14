import { handleProfile } from '@auth0/nextjs-auth0';

export default async function me(req, res) {
  try {
    await handleProfile(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
