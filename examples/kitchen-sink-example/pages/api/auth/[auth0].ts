import { randomBytes } from 'crypto';
import { handleAuth, handleCallback } from '@auth0/nextjs-auth0';

export default handleAuth({
  callback: handleCallback({
    afterCallback(req, res, session, state) {
      session.user.customProp = randomBytes(2000).toString('base64');
      return session;
    }
  }),
  onError(req, res, error) {
    console.error(error);
    res.status(error.status || 500).end('Check the console for the error');
  }
});
