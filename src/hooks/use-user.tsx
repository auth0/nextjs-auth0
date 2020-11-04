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

export type NullableUserProfile = UserProfile | null;

export interface UserContext {
  user: NullableUserProfile;
  loading: boolean;
}

const User = createContext<UserContext>({ user: null, loading: false });

export const useUser = (): UserContext => useContext<UserContext>(User);

type UserProviderProps = React.PropsWithChildren<{ user: NullableUserProfile }>;

export default ({ children, user: initialUser }: UserProviderProps): ReactElement<UserContext> => {
  const [user, setUser] = useState<NullableUserProfile>(() => initialUser); // with withAuth, initialUser gets populated
  const [loading, setLoading] = useState<boolean>(() => !initialUser); // if initialUser is populated, no loading needed

  useEffect((): void => {
    if (user) return; // if initialUser is populated, no loading needed

    (async (): Promise<void> => {
      const response = await fetch('/api/me');
      const result = response.ok ? await response.json() : null;

      setUser(result);
      setLoading(false);
    })();
  }, [user]);

  return <User.Provider value={{ user, loading }}>{children}</User.Provider>;
};
