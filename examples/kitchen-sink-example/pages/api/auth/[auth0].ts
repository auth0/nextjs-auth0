import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth({
  onError(req, res, error) {
    console.error(error);
    res.status(error.status || 500).end('Check the console for the error');
  }
});
