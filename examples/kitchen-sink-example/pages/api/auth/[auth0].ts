import { handleAuth } from '@auth0/nextjs-auth0';

export default handleAuth({
  login: {
    authorizationParams: { scope: 'openid email offline_access' },
    getLoginState() {
      return { foo: 'bar' };
    }
  },
  logout: { returnTo: 'https://example.com/foo' },
  callback: {
    async afterCallback(req, res, session) {
      console.log('After callback!!');
      return session;
    },
    authorizationParams: { scope: 'openid email' }
  },
  profile: {
    refetch: true,
    async afterRefetch(req, res, session) {
      console.log('After refetch!!');
      return session;
    }
  },
  onError(req, res, error) {
    console.error(error);
    res.status(error.status || 500).end('Check the console for the error');
  }
});
