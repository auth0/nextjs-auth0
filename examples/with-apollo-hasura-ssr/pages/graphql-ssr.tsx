import { NextPage } from 'next'
import Layout from '../components/Layout'
import UserList from '../components/UserQuery'
import auth0 from '../lib/auth0'
import useUser from '../lib/useUser'
import withApollo from '../lib/withApollo'
import withAuth from '../lib/withAuth'

type Props = Readonly<{ clientId: string; }>

const GraphQLSSR: NextPage<Props> = ({ clientId }: Props) => {
  const { user } = useUser()

  return (
    <Layout>
      <h1>GraphQL SSR</h1>

      <h2>Auth0 client Id</h2>
      <pre>{clientId}</pre>

      <h2>useUser result:</h2>
      <pre>{JSON.stringify(user, null, 2)}</pre>

      <h2>GraphQL result:</h2>
      <UserList />
    </Layout>
  )
}

// test we can pass props in despite the withA* wrappers.
GraphQLSSR.getInitialProps = async () => {
  const clientId = process.env.NEXT_PUBLIC_AUTH0_CLIENT_ID || 'AUTH0_CLIENT_ID-missing'
  return { clientId }
}

export default withApollo(withAuth(GraphQLSSR, auth0))
