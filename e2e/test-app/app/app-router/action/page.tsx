"use client"

import { useState } from "react"

import { testServerAction } from "./action"

export default function Profile() {
  const [status, setStatus] = useState("")

  return (
    <main>
      <input
        id="status"
        value={status}
        onChange={(e) => setStatus(e.target.value)}
      ></input>
      <button
        onClick={async () => {
          const { status } = await testServerAction()
          setStatus(status)
        }}
      >
        Call server action
      </button>
    </main>
  )
}
