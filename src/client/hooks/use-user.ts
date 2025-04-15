"use client";

import useSWR from "swr";

import type { User } from "../../types";

export function useUser() {
  const { data, error, isLoading, mutate } = useSWR<User, Error, string>(
    process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
    (...args) =>
      fetch(...args).then((res) => {
        if (!res.ok) {
          throw new Error(res.statusText || "Fetch error");
        }
        return res.json();
      })
  );

  if (error) {
    return {
      user: data,
      isLoading: false,
      error,
      invalidate: () => mutate()
    };
  }

  if (data) {
    return {
      user: data,
      isLoading: false,
      error: null,
      invalidate: () => mutate()
    };
  }

  return {
    user: null,
    isLoading,
    error: null,
    invalidate: () => mutate()
  };
}
