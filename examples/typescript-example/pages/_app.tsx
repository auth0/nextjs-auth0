import React from 'react';
import NextApp from 'next/app';
import type { AppProps } from 'next/app';

export default class App extends NextApp<AppProps> {
  render(): JSX.Element {
    const { pageProps, Component } = this.props;
    return <Component {...pageProps} />;
  }
}
