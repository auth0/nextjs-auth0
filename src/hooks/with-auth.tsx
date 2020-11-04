import React, { Component } from 'react';
import { NextApiRequest, NextApiResponse, NextPage, NextPageContext } from 'next';
import Router from 'next/router';

import { NullableUserProfile, useUser } from './use-user';
import { ISignInWithAuth0 } from '../instance';
import { createLoginUrl } from '../utils/url-helpers';

type RedirectToLoginProps = {
  render: () => React.ReactElement;
};

class RedirectToLogin extends Component<RedirectToLoginProps> {
  public constructor(props: RedirectToLoginProps) {
    super(props);
  }

  public componentDidMount(): void {
    window.location.assign(createLoginUrl(Router.pathname));
  }

  public render(): React.ReactElement {
    return this.props.render();
  }
}

type AuthenticatedProps = React.PropsWithChildren<{ user: NullableUserProfile }>;

export default function withAuth(
  InnerComponent: React.ElementType,
  redirect: () => React.ReactElement,
  instance: ISignInWithAuth0
): NextPage<AuthenticatedProps> {
  const Authenticated: NextPage<AuthenticatedProps> = (props) => {
    const { user } = useUser();

    if (!user) {
      return <RedirectToLogin render={redirect} />;
    }

    return <InnerComponent {...props} user={user} />;
  };

  Authenticated.getInitialProps = async (context: NextPageContext): Promise<AuthenticatedProps> => {
    if (!context.req) {
      const response = await fetch('/api/me');
      const result = response.ok ? await response.json() : null;

      return { user: result, children: undefined };
    }

    const session = await instance.getSession(context.req as NextApiRequest, context.res as NextApiResponse);

    if (!session || !session.user) {
      context.res?.writeHead(302, {
        Location: createLoginUrl(context.req.url)
      });
      context.res?.end();

      return { user: null, children: undefined };
    }

    return { user: session.user as NullableUserProfile, children: undefined };
  };

  return Authenticated;
}
