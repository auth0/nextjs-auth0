import React from 'react';
import Layout from '../components/layout';

export default function About() {
  return (
    <Layout>
      <h1>About</h1>
      <p>
        This is the about page, navigating between this page and <i>Home</i> is always pretty fast. However, when you
        navigate to the <i>Profile</i> page it takes more time because it uses SSR to fetch the user first;
      </p>
    </Layout>
  );
}
