import Layout from '../components/Layout'
import UserList from '../components/UserQuery'
import useUser from '../lib/useUser'
import withApollo from '../lib/withApollo'

const GraphQL = () => {
  const { user } = useUser()

  return (
    <Layout>
      <h1>GraphQL Static (client-side fetching)</h1>

      <h2>useUser result:</h2>
      <pre>{JSON.stringify(user, null, 2)}</pre>

      <h2>GraphQL result:</h2>
      <UserList />
    </Layout>
  )
}

export default withApollo(GraphQL, {
  // Disable apollo ssr fetching in favour of automatic static optimization
  ssr: false
})
