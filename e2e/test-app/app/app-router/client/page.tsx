"use client"

import { getAccessToken, useUser } from "@auth0/nextjs-auth0"

export default function Profile() {
  const { user, isLoading } = useUser()

  if (isLoading) {
    return (
      <main>
        <div>Loading...</div>
      </main>
    )
  }

  if (!user) {
    return (
      <main>
        <a href="/auth/login">Log in</a>
      </main>
    )
  }

  const handleForceRefresh = async () => {
    // TypeScript workaround: cast to any to use the overloaded signature
    await (getAccessToken as any)({ refresh: true })
  }

  return (
    <main>
      <h1>Welcome, {user?.email}!</h1>
      <button
        onClick={async () => {
          await getAccessToken()
        }}
      >
        Get token
      </button>
      <button
        onClick={handleForceRefresh}
      >
        Force refresh token
      </button>
    </main>
  )
}
