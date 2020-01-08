import React, { Component } from 'react';
import auth0 from '../lib/auth0';

export default function withAuth(InnerComponent) {
  return class Authenticated extends Component {
    static async getInitialProps({ req, res }) {
      const session = await auth0.getSession(req);
      if (!session || !session.user) {
        res.writeHead(302, {
          Location: '/api/login'
        });
        res.end();
        return;
      }

      return { user: session.user };
    }

    constructor(props) {
      super(props);
    }

    render() {
      return <div>{<InnerComponent {...this.props} user={this.props.user} />}</div>;
    }
  };
}
