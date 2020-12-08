import { handleLogout } from '@auth0/nextjs-auth0';

export default async function logout(req, res) {
  try {
    await handleLogout(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
