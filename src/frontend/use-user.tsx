import React, { ReactElement, useState, useEffect, useContext, createContext } from 'react';

export interface UserProfile {
  email?: string | null;
  email_verified?: boolean | null;
  name?: string | null;
  nickname?: string | null;
  picture?: string | null;
  sub?: string | null;
  updated_at?: string | null;
  [key: string]: unknown; // Any custom claim which could be in the profile
}

export interface UserContext {
  user?: UserProfile;
  loading: boolean;
}

type UserProviderProps = React.PropsWithChildren<{ user?: UserProfile; profileUrl?: string }>;

const User = createContext<UserContext>({ loading: false });

export type UseUser = () => UserContext;

export const useUser: UseUser = () => useContext<UserContext>(User);

export type UserProvider = (props: UserProviderProps) => ReactElement<UserContext>;

export default ({
  children,
  user: initialUser,
  profileUrl = '/api/auth/me' // TODO: Change to /api/auth/user
}: UserProviderProps): ReactElement<UserContext> => {
  const [user, setUser] = useState<UserProfile | undefined>(() => initialUser);
  const [loading, setLoading] = useState<boolean>(() => !initialUser);

  useEffect((): void => {
    if (user) return;

    (async (): Promise<void> => {
      const response = await fetch(profileUrl);
      const result = response.ok ? await response.json() : undefined;

      setUser(result);
      setLoading(false);
    })();
  }, [user]);

  return <User.Provider value={{ user, loading }}>{children}</User.Provider>;
};
