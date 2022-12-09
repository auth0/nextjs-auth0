'use client';
import React, { ReactElement, useContext, createContext } from 'react';

export type ConfigContext = {
  loginUrl?: string;
};

const Config = createContext<ConfigContext>({});

export type ConfigProviderProps = React.PropsWithChildren<ConfigContext>;
export type UseConfig = () => ConfigContext;
export const useConfig: UseConfig = () => useContext<ConfigContext>(Config);

export default ({
  children,
  loginUrl = process.env.NEXT_PUBLIC_AUTH0_LOGIN || '/api/auth/login'
}: ConfigProviderProps): ReactElement<ConfigContext> => {
  return <Config.Provider value={{ loginUrl }}>{children}</Config.Provider>;
};
