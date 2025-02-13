import type { GetServerSideProps, InferGetServerSidePropsType } from "next"

import { auth0 } from "@/lib/auth0"

export const getServerSideProps = (async (ctx) => {
  const session = await auth0.getSession(ctx.req)

  if (!session) return { props: { user: null } }

  return {
    props: { user: session.user ? { email: session.user.email! } : null },
  }
}) satisfies GetServerSideProps<{ user: { email: string } | null }>

export default function Page({
  user,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  if (!user) {
    return (
      <main>
        <a href="/auth/login">Log in</a>
      </main>
    )
  }

  return (
    <main>
      <h1>Welcome, {user.email}!</h1>
    </main>
  )
}
