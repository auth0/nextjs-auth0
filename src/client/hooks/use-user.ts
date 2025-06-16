"use client";

import useSWR from "swr";

import type { User } from "../../types";
import { normailizeWithBasePath } from "../../utils/pathUtils";

export function useUser() {
  const { data, error, isLoading, mutate } = useSWR<User, Error, string>(
    normailizeWithBasePath(
      process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"
    ),
    (...args) =>
      fetch(...args).then((res) => {
        if (!res.ok) {
          throw new Error("Unauthorized");
        }
        return res.json();
      })
  );

  if (error) {
    return {
      user: null,
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
    user: data,
    isLoading,
    error,
    invalidate: () => mutate()
  };
}
