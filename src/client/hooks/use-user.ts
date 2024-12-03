"use client"

import useSWR from "swr"

import type { User } from "../../types"

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

  // if we have the user loaded via the provider, return it
  if (data) {
    return {
      user: data,
      isLoading: false,
      error: null,
    }
  }

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
