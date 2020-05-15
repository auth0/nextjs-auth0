import React, { Component } from 'react';

import auth0 from '../lib/auth0';
import { fetchUser } from '../lib/user';
import createLoginUrl from '../lib/url-helper';
import RedirectToLogin from '../components/login-redirect';

export default function withAuth(InnerComponent) {
  return class Authenticated extends Component {
    static async getInitialProps(ctx) {
      if (!ctx.req) {
        const user = await fetchUser();
        return {
          user
        };
      }

      const session = await auth0.getSession(ctx.req);
      if (!session || !session.user) {
        ctx.res.writeHead(302, {
          Location: createLoginUrl(ctx.req.url)
        });
        ctx.res.end();
        return;
      }

      return { user: session.user };
    }

    constructor(props) {
      super(props);
    }

    render() {
      if (!this.props.user) {
        return <RedirectToLogin />;
      }

      return <div>{<InnerComponent {...this.props} user={this.props.user} />}</div>;
    }
  };
}
