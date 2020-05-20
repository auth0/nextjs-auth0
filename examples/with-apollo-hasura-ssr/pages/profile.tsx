import React from 'react'
import Layout from '../components/Layout'
import { UserContext } from '../components/UserProvider'
import useUser from '../lib/useUser'

function SessionCard({ user, loading }: UserContext) {
  if (loading) return <>Loading...</>
  if (user == null) return <>user == null</>

  return (
    <>
      <h1>Profile (Client)</h1>

      <section>
        <h3>Session (client rendered)</h3>
        <img src={user.picture} alt="user picture" />
        <p>nickname: {user.nickname}</p>
        <p>name: {user.name}</p>
        <pre>{JSON.stringify(user, null, 2)}</pre>
      </section>
    </>
  )
}

function Session() {
  const ctx = useUser(true)

  return (
    <Layout>
      <SessionCard {...ctx} />
    </Layout>
  )
}

export default Session
