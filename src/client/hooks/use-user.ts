"use client"

import useSWR from "swr"

import { User } from "../../server/user"

export function useUser() {
  const { data, error, isLoading } = useSWR<User, Error, string>(
    "/auth/profile",
    (...args) =>
      fetch(...args).then((res) => {
        if (!res.ok) {
          throw new Error("Unauthorized")
        }

        return res.json()
      })
  )

  if (error) {
    return {
      user: null,
      isLoading: false,
      error,
    }
  }

  return {
    user: data,
    isLoading,
    error,
  }
}
