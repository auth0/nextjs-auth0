import React from 'react';
import { UserProvider, UserProviderProps, UserProfile } from '../../src/frontend';

type FetchUserMock = {
  ok: boolean;
  json?: () => Promise<UserProfile>;
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

export const withUserProvider = ({ user, profileUrl }: UserProviderProps = {}): React.ComponentType => {
  return (props: any): React.ReactElement => <UserProvider {...props} user={user} profileUrl={profileUrl} />;
};

export const fetchUserMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve(user)
  });
};

export const fetchUserUnsuccessfulMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({
    ok: false
  });
};

export const fetchUserErrorMock = (): Promise<FetchUserMock> => Promise.reject(new Error('Error'));
