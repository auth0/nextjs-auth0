"use client";

import React from "react";
import { SWRConfig } from "swr";

import { User } from "../../types/index.js";

/**
 * Props for the Auth0Provider component.
 */
export type Auth0ProviderProps = {
  /**
   * Initial user data to populate the SWR cache.
   */
  user?: User;
  /**
   * Child components to render within the provider.
   */
  children: React.ReactNode;
  /**
   * Custom route for the profile endpoint.
   * Useful for multi-tenant applications where different tenants require different route configurations.
   * If not specified, falls back to the NEXT_PUBLIC_PROFILE_ROUTE environment variable or "/auth/profile".
   *
   * @example '/tenant-a/auth/profile'
   */
  profileRoute?: string;
};

export function Auth0Provider({
  user,
  children,
  profileRoute
}: Auth0ProviderProps) {
  const route =
    profileRoute || process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile";

  return (
    <SWRConfig
      value={{
        fallback: {
          [route]: user
        }
      }}
    >
      {children}
    </SWRConfig>
  );
}
