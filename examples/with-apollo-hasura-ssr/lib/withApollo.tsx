// From https://github.com/zeit/next.js/blob/6e77c071c7285ebe9998b56dbc1c76aaf67b6d2f/examples/with-apollo/lib/apollo.js
import { ApolloProvider } from '@apollo/react-hooks'
import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { ApolloClient } from 'apollo-client'
import { NextPage, NextPageContext } from 'next'
import Head from 'next/head'
import React, { useMemo } from 'react'
import initApolloClient from './apollo'
import auth0 from './auth0'

type WithApolloInnerProps<TProps> = TProps & {
  apolloClient: ApolloClient<NormalizedCacheObject>;
  apolloState: any;
}

type WithApolloProps = Readonly<{
  ssr: boolean;
}>

type WithApolloContext = NextPageContext & {
  apolloClient: ApolloClient<NormalizedCacheObject>;
}


/**
 * Function that computes Apollo authN headers based on whether we're server-side or client-side.
 */
async function getHeaders(ctx: WithApolloContext): Promise<Record<string, string> | null> {
  if (typeof window !== 'undefined') return null
  if (typeof ctx.req === 'undefined') return null

  // @ts-ignore
  const s = await auth0.getSession(ctx.req)
  if (s?.idToken == null) return null

  return {
    authorization: `Bearer ${s?.idToken}`
  }
}


/**
 * Creates and provides the apolloContext
 * to a next.js PageTree. Use it by wrapping
 * your PageComponent via HOC pattern.
 * @param {Function|Class} PageComponent
 * @param {Object} [config]
 * @param {Boolean} [config.ssr=true]
 */
export default function withApollo<P = {}, IP = P>(PageComponent: NextPage<P, IP>, { ssr }: WithApolloProps = { ssr: true }): NextPage<P, IP> {

  function WithApollo({ apolloClient, apolloState, ...pageProps }: WithApolloInnerProps<P>) {
    const client = useMemo(
      () => apolloClient || initApolloClient(apolloState, {}),
      [] // eslint-disable-line
    )
    return (
      <ApolloProvider client={client}>
        <PageComponent {...pageProps as any} />
      </ApolloProvider>
    )
  }

  // Set the correct displayName in development
  if (process.env.NODE_ENV !== 'production') {
    const displayName =
      PageComponent.displayName || PageComponent.name || 'Component'

    if (displayName === 'App') {
      console.warn('This withApollo HOC only works with PageComponents.')
    }

    WithApollo.displayName = `withApollo(${displayName})`
  }

  if (ssr || PageComponent.getInitialProps) {
    WithApollo.getInitialProps = async (ctx: WithApolloContext) => {
      const { AppTree } = ctx

      // Initialize ApolloClient, add it to the ctx object so
      // we can use it in `PageComponent.getInitialProp`.
      const apolloClient = (ctx.apolloClient = initApolloClient(null, await getHeaders(ctx)))

      // Run wrapped getInitialProps methods
      let pageProps = {}
      if (PageComponent.getInitialProps) {
        pageProps = await PageComponent.getInitialProps(ctx)
      }

      // Only on the server:
      if (typeof window === 'undefined') {
        // When redirecting, the response is finished.
        // No point in continuing to render
        if (ctx.res && ctx.res.finished) {
          return pageProps
        }

        // Only if ssr is enabled
        if (ssr) {
          try {
            // Run all GraphQL queries
            const { getDataFromTree } = await import('@apollo/react-ssr')
            await getDataFromTree(
              <AppTree
                pageProps={{
                  ...pageProps,
                  apolloClient
                }}
              />
            )
          } catch (error) {
            // Prevent Apollo Client GraphQL errors from crashing SSR.
            // Handle them in components via the data.error prop:
            // https://www.apollographql.com/docs/react/api/react-apollo.html#graphql-query-data-error
            console.error('Error while running `getDataFromTree`', error)
          }

          // getDataFromTree does not call componentWillUnmount
          // head side effect therefore need to be cleared manually
          Head.rewind()
        }
      }

      // Extract query data from the Apollo store
      const apolloState = apolloClient.cache.extract()

      return {
        ...pageProps,
        apolloState
      }
    }
  }

  return WithApollo as NextPage<P, IP>
}
