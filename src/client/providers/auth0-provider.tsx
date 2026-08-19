"use client";

import React from "react";
import { SWRConfig } from "swr";

import type { AnonymousSession, User } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Props for the Auth0Provider component.
 * Adds anonymousSession prop for seeding SWR cache (SSR fallback, no loading flash).
 */
export type Auth0ProviderProps = {
  /**
   * Initial user data to populate the SWR cache for the profile endpoint.
   */
  user?: User;
  /**
   * Initial anonymous session data to populate the SWR cache.
   * Prevents loading flash when anonymous session is fetched server-side.
   * Optional; if omitted, SWR fetches normally.
   */
  anonymousSession?: AnonymousSession | null;
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
  /**
   * Custom route for the anonymous session endpoint.
   * If not specified, falls back to the NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE environment variable or "/auth/anonymous-session".
   *
   * @example '/tenant-a/auth/anonymous-session'
   */
  anonymousSessionRoute?: string;
};

export function Auth0Provider({
  user,
  anonymousSession,
  children,
  profileRoute,
  anonymousSessionRoute
}: Auth0ProviderProps) {
  // Resolve profile route
  const profileKey = normalizeWithBasePath(
    profileRoute || process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"
  );

  // Resolve anonymous session route
  const anonKey = normalizeWithBasePath(
    anonymousSessionRoute ||
      process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE ||
      "/auth/anonymous-session"
  );

  // Build SWR fallback cache with both user and anonymous session
  // Avoids loading flashes when both are available from server-side fetch
  const fallback: Record<string, unknown> = {
    [profileKey]: user
  };

  // Seed anonymous session only if provided (may be null or undefined)
  if (anonymousSession !== undefined) {
    fallback[anonKey] = anonymousSession;
  }

  return <SWRConfig value={{ fallback }}>{children}</SWRConfig>;
}
