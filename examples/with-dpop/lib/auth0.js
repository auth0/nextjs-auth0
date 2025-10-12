import { Auth0Client } from '@auth0/nextjs-auth0';
import * as oauth from 'oauth4webapi';

const dpopKeyPair = await oauth.generateKeyPair('ES256');

// Initialize the Auth0 client
export const auth0 = new Auth0Client({
  authorizationParameters: {
    scope: process.env.AUTH0_SCOPE,
    audience: process.env.AUTH0_AUDIENCE
  },
  useDpop: true,
  dpopKeyPair,
  allowInsecureRequests: process.env.NODE_ENV === 'development'
});

// Export the key pair for use in API server validation
export { dpopKeyPair };
