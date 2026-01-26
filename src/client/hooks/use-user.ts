"use client";

import useSWR from "swr";

import type { User } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Options for the useUser hook.
 */
export type UseUserOptions = {
  /**
   * Custom route for the profile endpoint.
   * Useful for multi-tenant applications where different tenants require different route configurations.
   * If not specified, falls back to the NEXT_PUBLIC_PROFILE_ROUTE environment variable or "/auth/profile".
   *
   * @example '/tenant-a/auth/profile'
   */
  route?: string;
};

export function useUser(options: UseUserOptions = {}) {
  const { data, error, isLoading, mutate } = useSWR<User, Error, string>(
    normalizeWithBasePath(
      options.route || process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"
    ),
    (...args) =>
      fetch(...args).then((res) => {
        if (!res.ok) {
          throw new Error("Unauthorized");
        }

        if (res.status === 204) {
          return null;
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
