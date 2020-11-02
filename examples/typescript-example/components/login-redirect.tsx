import Router from 'next/router';
import React, { Component } from 'react';

import Layout from '../components/layout';
import createLoginUrl from '../lib/url-helper';

export default class RedirectToLogin extends Component {
  componentDidMount(): void {
    window.location.assign(createLoginUrl(Router.pathname));
  }

  render(): React.ReactElement {
    return (
      <Layout>
        <div>Signing you in...</div>
      </Layout>
    );
  }
}
