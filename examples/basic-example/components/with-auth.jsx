import React from 'react';
import { useUser } from '@auth0/nextjs-auth0';

import auth0 from '../lib/auth0';
import createLoginUrl from '../lib/url-helper';
import RedirectToLogin from '../components/login-redirect';

export default function withAuth(InnerComponent) {
  const Authenticated = (props) => {
    const { user } = useUser();

    if (!user) {
      return <RedirectToLogin />; // do you need a "redirecting to login" route?
    }

    return <InnerComponent {...props} user={user} />;
  };

  Authenticated.getInitialProps = async (ctx) => {
    if (!ctx.req) {
      const response = await fetch('/api/me');
      const result = response.ok ? await response.json() : null;

      return { user: result };
    }

    const session = await auth0.getSession(ctx.req, ctx.res);

    if (!session || !session.user) {
      ctx.res.writeHead(302, {
        Location: createLoginUrl(ctx.req.url)
      });
      ctx.res.end();
      return;
    }

    return { user: session.user };
  };

  return Authenticated;
}
