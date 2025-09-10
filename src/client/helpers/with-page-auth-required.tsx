"use client";

import React, { ComponentType, JSX, useEffect } from "react";
import { useRouter as usePagesRouter } from "next/compat/router.js";
import { usePathname } from "next/navigation.js";

import type { User } from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";
import { useUser } from "../hooks/use-user.js";

const defaultOnRedirecting = (): JSX.Element => <></>;
const defaultOnError = (): JSX.Element => <></>;

/**
 * Options to customize the withPageAuthRequired higher order component.
 */
export interface WithPageAuthRequiredOptions {
  /**
   * ```js
   * withPageAuthRequired(Profile, {
   *   returnTo: '/profile'
   * });
   * ```
   *
   * Add a path to return the user to after login.
   */
  returnTo?: string;
  /**
   * ```js
   * withPageAuthRequired(Profile, {
   *   onRedirecting: () => <div>Redirecting...</div>
   * });
   * ```
   *
   * Render a message to show that the user is being redirected.
   */
  onRedirecting?: () => JSX.Element;
  /**
   * ```js
   * withPageAuthRequired(Profile, {
   *   onError: error => <div>Error: {error.message}</div>
   * });
   * ```
   *
   * Render a fallback in case of error fetching the user from the profile API route.
   */
  onError?: (error: Error) => JSX.Element;
}

export interface UserProps {
  user: User;
}

/**
 * ```js
 * const MyProtectedPage = withPageAuthRequired(MyPage);
 * ```
 *
 * When you wrap your pages in this higher order component and an anonymous user visits your page,
 * they will be redirected to the login page and then returned to the page they were redirected from (after login).
 */
export type WithPageAuthRequired = <P extends object>(
  Component: ComponentType<P & UserProps>,
  options?: WithPageAuthRequiredOptions
) => React.FC<P>;

export const withPageAuthRequired: WithPageAuthRequired = (
  Component,
  options = {}
) => {
  return function WithPageAuthRequired(props): JSX.Element {
    const {
      returnTo,
      onRedirecting = defaultOnRedirecting,
      onError = defaultOnError
    } = options;
    const loginUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login"
    );
    const { user, error, isLoading } = useUser();
    const pagesRouter = usePagesRouter();
    const pathname = usePathname();

    useEffect(() => {
      if (pagesRouter && !pagesRouter.isReady) return;
      if ((user && !error) || isLoading) return;

      let returnToPath: string;

      if (!returnTo) {
        const currentLocation = window.location;
        returnToPath = pathname + currentLocation.search + currentLocation.hash;
      } else {
        returnToPath = returnTo;
      }

      window.location.assign(
        `${loginUrl}?returnTo=${encodeURIComponent(returnToPath)}`
      );
    }, [user, error, isLoading]);

    if (error) return onError(error);
    if (user) {
      const componentProps = {
        ...props,
        user
      } as React.ComponentProps<typeof Component> & UserProps;
      return <Component {...componentProps} />;
    }

    return onRedirecting();
  };
};
