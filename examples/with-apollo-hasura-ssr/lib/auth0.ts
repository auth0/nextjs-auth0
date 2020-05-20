import { initAuth0 } from '@auth0/nextjs-auth0'
import IAuth0Settings from '@auth0/nextjs-auth0/dist/settings'

function fail(m: string): string { throw new Error(m) }

const common: IAuth0Settings = {
  clientId: process.env.NEXT_PUBLIC_AUTH0_CLIENT_ID || fail('Missing "NEXT_PUBLIC_AUTH0_CLIENT_ID" env var'),
  domain: process.env.NEXT_PUBLIC_AUTH0_DOMAIN || fail('Missing "NEXT_PUBLIC_AUTH0_DOMAIN" env var'),
  scope: process.env.NEXT_PUBLIC_AUTH0_SCOPE || fail('Missing "NEXT_PUBLIC_AUTH0_SCOPE" env var'),
  postLogoutRedirectUri: process.env.NEXT_PUBLIC_POST_LOGOUT_REDIRECT_URI || fail('Missing "NEXT_PUBLIC_POST_LOGOUT_REDIRECT_URI" env var'),
  redirectUri: process.env.NEXT_PUBLIC_REDIRECT_URI || fail('Missing "NEXT_PUBLIC_REDIRECT_URI" env var'),
}

export default (typeof window !== 'undefined')
  ? initAuth0(common)
  : initAuth0({
    ...common,
    audience: process.env.API_AUDIENCE,
    clientSecret: process.env.AUTH0_CLIENT_SECRET || fail('Missing "AUTH0_CLIENT_SECRET" env var'),
    session: {
      cookieSecret: process.env.SESSION_COOKIE_SECRET || fail('Missing "SESSION_COOKIE_SECRET" env var'),
      cookieLifetime: process.env.SESSION_COOKIE_LIFETIME && parseInt(process.env.SESSION_COOKIE_LIFETIME, 10) || 7200,
      storeIdToken: true,
      storeRefreshToken: true,
      storeAccessToken: true
    }
  })
