"use client"

import useSWR from "swr"

import { User } from "../../server/user"

export function useUser() {
  const { data, error, isLoading } = useSWR<User, {}, string>(
    "/auth/profile",
    (...args) => fetch(...args).then((res) => res.json())
  )

  return {
    user: data,
    isLoading,
    error,
  }
}
