import Layout from '../components/Layout'

function Home() {
  return (
    <Layout>
      <h1>Next.js + Auth0 + Hasura (Home: Simple)</h1>
      <p>
        To test the login click in <i>Login</i>
      </p>
      <p>
        Once you have logged in you should be able to see the logout link and
        the graphql/profile demo pages
      </p>
    </Layout>
  )
}

export default Home
