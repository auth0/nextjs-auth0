import { handleAuth, handleLogin, handleCallback } from '@auth0/nextjs-auth0';

export default handleAuth({
  login: handleLogin({
    authorizationParams: { redirect_uri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback` }
  }),
  callback: handleCallback({
    authorizationParams: { redirect_uri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback` }
  })
});
