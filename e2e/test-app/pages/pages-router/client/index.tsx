import { useState } from "react"
import { getAccessToken, useUser } from "@auth0/nextjs-auth0"

export default function Profile() {
  const { user, isLoading } = useUser()
  const [token, setToken] = useState("")

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

  return (
    <main>
      <h1>Welcome, {user?.email}!</h1>
      <input
        id="token"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      ></input>
      <button
        onClick={async () => {
          const token = await getAccessToken()
          setToken(token)
        }}
      >
        Get token
      </button>
    </main>
  )
}
