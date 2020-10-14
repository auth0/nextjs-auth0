import React, { ReactElement } from 'react';
import fetch from 'isomorphic-unfetch';

export interface UserProfile {
  email: string | null | undefined;

  email_verified: boolean | null | undefined;

  name: string | null | undefined;

  nickname: string | null | undefined;

  picture: string | null | undefined;

  sub: string | null | undefined;

  updated_at: string | null | undefined;

  /** Any custom claim which could be in the profile */
  [key: string]: unknown;
}

interface UserContext {
  user: UserProfile | null;

  loading: boolean;
}

// Use a global to save the user, so we don't have to fetch it again after page navigations
let userState: UserProfile;

const User = React.createContext<UserContext>({ user: null, loading: false });

export const fetchUser = async (): Promise<UserProfile> => {
  if (userState !== undefined) {
    return userState;
  }

  const res = await fetch('/api/me');
  userState = res.ok ? await res.json() : null;
  return userState;
};

type UserProviderProps = { value: UserContext; children: React.ReactNode };

export const UserProvider = ({ value, children }: UserProviderProps): ReactElement<UserContext> => {
  const { user } = value;

  // If the user was fetched in SSR add it to userState so we don't fetch it again
  React.useEffect(() => {
    if (!userState && user) {
      userState = user;
    }
  }, []);

  return <User.Provider value={value}>{children}</User.Provider>;
};

export const useUser = (): UserContext => React.useContext(User);

export const useFetchUser = (): UserContext => {
  const [data, setUser] = React.useState({
    user: userState || null,
    loading: userState === undefined
  });

  React.useEffect(() => {
    if (userState !== undefined) {
      return;
    }

    let isMounted = true;

    fetchUser().then((user) => {
      // Only set the user if the component is still mounted
      if (isMounted) {
        setUser({ user, loading: false });
      }
    });

    return () => {
      isMounted = false;
    };
  }, [userState]);

  return data;
};
