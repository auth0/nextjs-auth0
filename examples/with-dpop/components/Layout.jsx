import React from 'react';
import { Container } from 'reactstrap';
import Head from 'next/head';
import PropTypes from 'prop-types';

import NavBar from './NavBar';

const Layout = ({ children }) => (
  <>
    <Head>
      <link
        rel="stylesheet"
        href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossOrigin="anonymous"
      />
      <link rel="stylesheet" href="https://cdn.auth0.com/js/auth0-samples-theme/1.0/css/auth0-theme.min.css" />
      <title>DPoP Example - Next.js</title>
    </Head>
    <main id="app" className="d-flex flex-column h-100" data-testid="layout">
      <NavBar />
      <Container className="flex-grow-1 mt-5">{children}</Container>
    </main>
  </>
);

Layout.propTypes = {
  children: PropTypes.node.isRequired
};

export default Layout;
