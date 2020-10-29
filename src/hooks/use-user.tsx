import React, { ReactElement, useState, useEffect, useContext, createContext } from 'react';

declare const fetch: any;

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

interface UserContext {
  user: UserProfile | null;
  loading: boolean;
}

type UserProviderProps = {
  children: React.ReactNode;
  user: UserProfile;
};

const User = createContext<UserContext>({ user: null, loading: false });

export const useUser = (): UserContext => useContext<UserContext>(User);

export const UserProvider = ({ children, user: initialUser }: UserProviderProps): ReactElement<UserContext> => {
  const [user, setUser] = useState<UserProfile>(() => initialUser); // if used withAuth, initialUser is populated
  const [loading, setLoading] = useState<boolean>(() => !initialUser); // if initialUser is populated, no loading needed

  useEffect((): void => {
    if (user) return; // if initialUser is populated, no loading required

    (async (): Promise<void> => {
      const response = await fetch('/api/me');
      const result = response.ok ? await response.json() : null;

      setUser(result);
      setLoading(false);
    })();
  }, [user]);

  return <User.Provider value={{ user, loading }}>{children}</User.Provider>;
};
