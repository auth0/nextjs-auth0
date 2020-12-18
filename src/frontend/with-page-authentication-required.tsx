import React, { ComponentType, useEffect, FC } from 'react';
import { useRouter } from 'next/router';

import { useUser } from './use-user';

/**
 * @ignore
 */
const defaultOnRedirecting = (): JSX.Element => <></>;

/**
 * Options for the withAuthenticationRequired Higher Order Component
 */
export interface WithPageAuthenticationRequiredOptions {
  /**
   * ```js
   * withAuthenticationRequired(Profile, {
   *   returnTo: '/profile'
   * })
   * ```
   *
   * or
   *
   * ```js
   * withAuthenticationRequired(Profile, {
   *   returnTo: () => router.pathname
   * })
   * ```
   *
   * Add a path for the `onRedirectCallback` handler to return the user to after login.
   */
  returnTo?: string;
  /**
   * The path of your custom login API route. // TODO: Complete
   */
  loginUrl?: string;
  /**
   * ```js
   * withAuthenticationRequired(Profile, {
   *   onRedirecting: () => <div>Redirecting you to the login...</div>
   * })
   * ```
   *
   * Render a message to show that the user is being redirected to the login.
   */
  onRedirecting?: () => JSX.Element;
}

/**
 * ```js
 * const MyProtectedPage = withAuthenticationRequired(MyPage);
 * ```
 *
 * When you wrap your pages in this Higher Order Component and an anonymous user visits your page
 * they will be redirected to the login page and returned to the page they were redirected from after login.
 */
const withPageAuthenticationRequired = <P extends object>(
  Component: ComponentType<P>,
  options: WithPageAuthenticationRequiredOptions = {}
): FC<P> => {
  return function WithAuthenticationRequired(props: P): JSX.Element {
    const router = useRouter();
    const { returnTo = router.asPath, onRedirecting = defaultOnRedirecting, loginUrl = '/api/auth/login' } = options;
    const { user, loading } = useUser();

    useEffect(() => {
      if (user || loading) return;

      (async (): Promise<void> => {
        await router.push(`${loginUrl}?returnTo=${encodeURIComponent(returnTo)}`);
      })();
    }, [user, loading, router, loginUrl, returnTo]);

    return user ? <Component {...props} /> : onRedirecting();
  };
};

export default withPageAuthenticationRequired;
