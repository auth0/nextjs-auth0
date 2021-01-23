import React, { ReactElement, useContext, createContext } from 'react';
import { useRouter } from 'next/router';

export type ConfigContext = {
  loginUrl?: string;
  returnTo?: string;
};

const Config = createContext<ConfigContext>({});

export type ConfigProviderProps = React.PropsWithChildren<ConfigContext>;
export type UseConfig = () => ConfigContext;
export const useConfig: UseConfig = () => useContext<ConfigContext>(Config);

export default ({
  children,
  loginUrl = process.env.NEXT_PUBLIC_AUTH0_LOGIN || '/api/auth/login',
  returnTo = process.env.NEXT_PUBLIC_AUTH0_POST_LOGIN_REDIRECT
}: ConfigProviderProps): ReactElement<ConfigContext> => {
  const router = useRouter();
  return <Config.Provider value={{ loginUrl, returnTo: returnTo || router.asPath }}>{children}</Config.Provider>;
};
