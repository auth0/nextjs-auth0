import React, { ReactElement, useState, useEffect, useCallback, useContext, createContext } from 'react';

import ConfigProvider, { ConfigContext } from './use-config';

/**
 * The user claims returned from the {@link useUser} hook.
 *
 * @category Client
 */
export interface UserProfile {
  email?: string | null;
  email_verified?: boolean | null;
  name?: string | null;
  nickname?: string | null;
  picture?: string | null;
  sub?: string | null;
  updated_at?: string | null;
  org_id?: string | null;
  [key: string]: unknown; // Any custom claim which could be in the profile
}

/**
 * The user context returned from the {@link useUser} hook.
 *
 * @category Client
 */
export type UserContext = {
  user?: UserProfile;
  error?: Error;
  isLoading: boolean;
  checkSession: () => Promise<void>;
};

/**
 * The error thrown by the user fetcher.
 *
 * The `status` property contains the status code of the response. It is `0` when the request fails, e.g. due to being
 * offline.
 *
 * This error is not thrown when the status code of the response is `401`, because that means the user is not
 * authenticated.
 *
 * @category Client
 */
export class RequestError extends Error {
  public status: number;

  /* istanbul ignore next */
  constructor(status: number) {
    super();
    this.status = status;
    Object.setPrototypeOf(this, RequestError.prototype);
  }
}

/**
 * @ignore
 */
type UserFetcher = (url: string) => Promise<UserProfile | undefined>;

/**
 * Configure the {@link UserProvider} component.
 *
 * If you have any server-side rendered pages (eg. using `getServerSideProps`), you should get the user from the server
 * side session and pass it to the `<UserProvider>` component via `pageProps` - this will refill the {@link useUser}
 * hook with the {@link UserProfile} object. eg
 *
 * ```js
 * // pages/_app.js
 * import React from 'react';
 * import { UserProvider } from '@auth0/nextjs-auth0';
 *
 * export default function App({ Component, pageProps }) {
 *   // If you've used `withPageAuthRequired`, pageProps.user can pre-populate the hook
 *   // if you haven't used `withPageAuthRequired`, pageProps.user is undefined so the hook
 *   // fetches the user from the API route
 *   const { user } = pageProps;
 *
 *   return (
 *     <UserProvider user={user}>
 *       <Component {...pageProps} />
 *     </UserProvider>
 *   );
 * }
 * ```
 *
 * If you have used a custom url for your {@link HandleProfile} API Route handler (the default is `/api/auth/me`) then
 * you should specify it here in the `profileUrl` option.
 *
 * @category Client
 */
export type UserProviderProps = React.PropsWithChildren<
  { user?: UserProfile; profileUrl?: string; fetcher?: UserFetcher } & ConfigContext
>;

/**
 * @ignore
 */
const missingUserProvider = 'You forgot to wrap your app in <UserProvider>';

/**
 * @ignore
 */
export const UserContext = createContext<UserContext>({
  get user(): never {
    throw new Error(missingUserProvider);
  },
  get error(): never {
    throw new Error(missingUserProvider);
  },
  get isLoading(): never {
    throw new Error(missingUserProvider);
  },
  checkSession: (): never => {
    throw new Error(missingUserProvider);
  }
});

/**
 * The `useUser` hook, which will get you the {@link UserProfile} object from the server-side session by requesting it
 * from the {@link HandleProfile} API Route handler.
 *
 * ```js
 * // pages/profile.js
 * import Link from 'next/link';
 * import { useUser } from '@auth0/nextjs-auth0';
 *
 * export default function Profile() {
 *   const { user, error, isLoading } = useUser();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *   if (error) return <div>{error.message}</div>;
 *   if (!user) return <Link href="/api/auth/login"><a>Login</a></Link>;
 *   return <div>Hello {user.name}, <Link href="/api/auth/logout"><a>Logout</a></Link></div>;
 * }
 * ```
 *
 * @category Client
 */
export type UseUser = () => UserContext;

/**
 * @ignore
 */
export const useUser: UseUser = () => useContext<UserContext>(UserContext);

/**
 * To use the {@link useUser} hook. You must wrap your application in a `<UserProvider>` component.
 *
 * @category Client
 */
export type UserProvider = (props: UserProviderProps) => ReactElement<UserContext>;

/**
 * @ignore
 */
type UserProviderState = {
  user?: UserProfile;
  error?: Error;
  isLoading: boolean;
};

/**
 * @ignore
 */
const userFetcher: UserFetcher = async (url) => {
  let response;
  try {
    response = await fetch(url);
  } catch {
    throw new RequestError(0); // Network error
  }
  if (response.ok) {
    return response.json();
  } else if (response.status === 401) {
    return undefined;
  }
  throw new RequestError(response.status);
};

export default ({
  children,
  user: initialUser,
  profileUrl = process.env.NEXT_PUBLIC_AUTH0_PROFILE || '/api/auth/me',
  loginUrl,
  fetcher = userFetcher
}: UserProviderProps): ReactElement<UserContext> => {
  const [state, setState] = useState<UserProviderState>({ user: initialUser, isLoading: !initialUser });

  const checkSession = useCallback(async (): Promise<void> => {
    try {
      const user = await fetcher(profileUrl);
      setState((previous) => ({ ...previous, user, error: undefined }));
    } catch (error) {
      setState((previous) => ({ ...previous, error: error as Error }));
    }
  }, [profileUrl]);

  useEffect((): void => {
    if (state.user) return;
    (async (): Promise<void> => {
      await checkSession();
      setState((previous) => ({ ...previous, isLoading: false }));
    })();
  }, [state.user]);

  const { user, error, isLoading } = state;

  return (
    <ConfigProvider loginUrl={loginUrl}>
      <UserContext.Provider value={{ user, error, isLoading, checkSession }}>{children}</UserContext.Provider>
    </ConfigProvider>
  );
};
