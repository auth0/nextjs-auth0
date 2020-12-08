import React, { ReactElement, useState, useEffect, useContext, createContext } from 'react';

export interface UserProfile {
  email: string | null | undefined;
  email_verified: boolean | null | undefined;
  name: string | null | undefined;
  nickname: string | null | undefined;
  picture: string | null | undefined;
  sub: string | null | undefined;
  updated_at: string | null | undefined;
  [key: string]: unknown; // Any custom claim which could be in the profile
}

export interface UserContext {
  user: UserProfile | null;
  loading: boolean;
}

type UserProviderProps = React.PropsWithChildren<{ user: UserProfile | null; profileUrl?: string }>;

const User = createContext<UserContext>({ user: null, loading: false });

export type UseUser = () => UserContext;

export const useUser: UseUser = () => useContext<UserContext>(User);

export type UserProvider = (props: UserProviderProps) => ReactElement<UserContext>;

export default ({
  children,
  user: initialUser,
  profileUrl = '/api/auth/me'
}: UserProviderProps): ReactElement<UserContext> => {
  const [user, setUser] = useState<UserProfile | null>(() => initialUser); // if used withAuth, initialUser is populated
  const [loading, setLoading] = useState<boolean>(() => !initialUser); // if initialUser is populated, no loading needed

  useEffect((): void => {
    if (user) return; // if initialUser is populated, no loading required

    (async (): Promise<void> => {
      const response = await fetch(profileUrl);
      const result = response.ok ? await response.json() : null;

      setUser(result);
      setLoading(false);
    })();
  }, [user]);

  return <User.Provider value={{ user, loading }}>{children}</User.Provider>;
};
