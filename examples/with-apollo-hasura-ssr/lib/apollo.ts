import { InMemoryCache, NormalizedCacheObject } from 'apollo-cache-inmemory'
import { ApolloClient } from 'apollo-client'
import { HttpLink } from 'apollo-link-http'

let apolloClient: ApolloClient<NormalizedCacheObject> | null = null

/**
 * Creates and configures the ApolloClient
 */
function createApolloClient(initialState: NormalizedCacheObject, headers: Record<string, string>) {
  const serverURL = typeof window === 'undefined'
    ? process.env.HASURA_GRAPHQL_URL
    : `${window.location.origin}/api/graphql`

  return new ApolloClient({
    ssrMode: typeof window === 'undefined', // Disables forceFetch on the server (so queries are only run once)
    link: new HttpLink({
      uri: serverURL,
      credentials: 'include',
      fetch,
      headers
    }),
    cache: new InMemoryCache().restore(initialState),
  })
}

/**
 * Always creates a new apollo client on the server
 * Creates or reuses apollo client in the browser.
 * @param  {Object} initialState
 */
export default function initApolloClient(initialState: NormalizedCacheObject | null, headers: Record<string, string> | null) {
  // Make sure to create a new client for every server-side request so that data
  // isn't shared between connections (which would be bad)
  if (typeof window === 'undefined') {
    return createApolloClient(initialState || {}, headers || {})
  }

  // Reuse client on the client-side
  if (!apolloClient) {
    apolloClient = createApolloClient(initialState || {}, headers || {})
  }

  return apolloClient
}
