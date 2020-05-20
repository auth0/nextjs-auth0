import React from 'react'
import Layout from '../components/Layout'
import useUser from '../lib/useUser'
import withAuth from '../lib/withAuth'

function ProfileProtected() {
  console.info('render ProfileSSR')

  const { user } = useUser()

  if (user == null) throw new Error('Expected user != null since we have \'withAuth\' wrapping this Page')

  return (
    <Layout>
      <h1>Profile (SSR)</h1>

      <div>
        <h3>Session (server rendered)</h3>
        <img src={user.picture} alt="user picture" />
        <p>nickname: {user.nickname}</p>
        <p>name: {user.name}</p>
      </div>
    </Layout>
  )
}

export default withAuth(ProfileProtected)
