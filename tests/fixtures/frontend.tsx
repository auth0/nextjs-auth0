import React from 'react';

import {
  ConfigProvider,
  ConfigProviderProps,
  RequestError,
  UserProvider,
  UserProviderProps,
  UserProfile
} from '../../src/client';

type FetchUserMock = {
  ok: boolean;
  status: number;
  json?: () => Promise<UserProfile | undefined>;
};

export const user: UserProfile = {
  email: 'foo@example.com',
  email_verified: true,
  name: 'foo',
  nickname: 'foo',
  picture: 'foo.jpg',
  sub: '1',
  updated_at: null
};

export const withUserProvider = ({
  user,
  profileUrl,
  loginUrl,
  fetcher
}: UserProviderProps = {}): React.ComponentType => {
  return (props: any): React.ReactElement => (
    <UserProvider {...props} user={user} profileUrl={profileUrl} loginUrl={loginUrl} fetcher={fetcher} />
  );
};

export const fetchUserMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(user)
  });
};

export const fetchUserUnauthorizedMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({
    ok: true,
    status: 204,
    json: () => Promise.resolve(undefined)
  });
};

export const fetchUserErrorMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({
    ok: false,
    status: 500,
    json: () => Promise.resolve(undefined)
  });
};

export const fetchUserNetworkErrorMock = (): Promise<FetchUserMock> => {
  return Promise.reject(new RequestError(0));
};

export const withConfigProvider = ({ loginUrl }: ConfigProviderProps = {}): React.ComponentType => {
  return (props: any): React.ReactElement => <ConfigProvider {...props} loginUrl={loginUrl} />;
};
