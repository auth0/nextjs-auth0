import { Auth0Client } from '@auth0/nextjs-auth0/server';
import * as oauth from 'oauth4webapi';

// Generate DPoP key pair if environment variables are not set
let dpopKeyPair;
if (process.env.USE_DPOP === 'true' && !process.env.AUTH0_DPOP_PRIVATE_KEY) {
  console.info('Generating DPoP key pair for demonstration...');
  dpopKeyPair = await oauth.generateKeyPair('ES256');
}

// Initialize the Auth0 client
export const auth0 = new Auth0Client({
  // Options are loaded from environment variables by default
  // Ensure necessary environment variables are properly set
  // domain: process.env.AUTH0_DOMAIN,
  // clientId: process.env.AUTH0_CLIENT_ID,
  // clientSecret: process.env.AUTH0_CLIENT_SECRET,
  // appBaseUrl: process.env.APP_BASE_URL,
  // secret: process.env.AUTH0_SECRET,
  authorizationParameters: {
    // In v4, the AUTH0_SCOPE and AUTH0_AUDIENCE environment variables are no longer automatically picked up by the SDK.
    // Instead, we need to provide the values explicitly.
    scope: process.env.AUTH0_SCOPE,
    audience: process.env.AUTH0_AUDIENCE
  },
  // DPoP configuration - enable if USE_DPOP environment variable is set to true
  useDpop: process.env.USE_DPOP === 'true',
  ...(dpopKeyPair && { dpopKeyPair })
});

// Export the key pair for use in API server validation
export { dpopKeyPair };