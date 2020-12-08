import { handleCallback } from '@auth0/nextjs-auth0';

export default async function callback(req, res) {
  try {
    await handleCallback(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
