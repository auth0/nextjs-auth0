import React, { ComponentType, useEffect } from 'react';
import { useRouter } from 'next/router';

import { useUser } from './use-user';

/**
 * @ignore
 */
const defaultOnRedirecting = (): JSX.Element => <></>;

/**
 * Options for the withCSRAuthRequired Higher Order Component
 */
export interface WithCSRAuthRequiredOptions {
  /**
   * ```js
   * withCSRAuthRequired(Profile, {
   *   returnTo: '/profile'
   * })
   * ```
   *
   * Add a path to return the user to after login.
   */
  returnTo?: string;
  /**
   * ```js
   * withCSRAuthRequired(Profile, {
   *   loginUrl: '/api/login'
   * })
   * ```
   * The path of your custom login API route.
   */
  loginUrl?: string;
  /**
   * ```js
   * withCSRAuthRequired(Profile, {
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
 * const MyProtectedPage = withCSRAuthRequired(MyPage);
 * ```
 *
 * When you wrap your pages in this Higher Order Component and an anonymous user visits your page
 * they will be redirected to the login page and then returned to the page they were redirected from (after login).
 */
const withCSRAuthRequired = <P extends object>(
  Component: ComponentType<P>,
  options: WithCSRAuthRequiredOptions = {}
): React.FC<P> => {
  return function WithCSRAuthRequired(props: P): JSX.Element {
    const router = useRouter();
    const { returnTo = router.asPath, onRedirecting = defaultOnRedirecting, loginUrl = '/api/auth/login' } = options;
    const { user, loading } = useUser();

    useEffect(() => {
      if (user || loading) return;

      (async (): Promise<void> => {
        await router.push(`${loginUrl}?returnTo=${returnTo}`);
      })();
    }, [user, loading, router, loginUrl, returnTo]);

    return user ? <Component {...props} /> : onRedirecting();
  };
};

export default withCSRAuthRequired;
