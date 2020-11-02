import React from 'react';
import { NextPage, NextPageContext } from 'next';
import { UserProfile, useUser } from '@auth0/nextjs-auth0';

import auth0 from '../lib/auth0';
import createLoginUrl from '../lib/url-helper';
import RedirectToLogin from '../components/login-redirect';

type AuthenticatedProps = React.PropsWithChildren<{ user?: UserProfile }>;

export default function withAuth(
  InnerComponent: React.ElementType | React.FunctionComponent
): NextPage<AuthenticatedProps> {
  const Authenticated: NextPage<AuthenticatedProps> = (props) => {
    const { user } = useUser();

    if (!user) {
      return <RedirectToLogin />; // do you need a "redirecting to login" route?
    }

    return <InnerComponent {...props} user={user} />;
  };

  Authenticated.getInitialProps = async (context: NextPageContext): Promise<AuthenticatedProps> => {
    if (!context.req) {
      const response = await fetch('/api/me');
      const result = response.ok ? await response.json() : null;

      return { user: result, children: undefined };
    }

    const session = await auth0.getSession(context.req, context.res);

    if (!session || !session.user) {
      context.res.writeHead(302, {
        Location: createLoginUrl(context.req.url)
      });
      context.res.end();

      return;
    }

    return { user: session.user, children: undefined };
  };

  return Authenticated;
}
