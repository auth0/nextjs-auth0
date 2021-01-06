import React from 'react';
import { UserProfile, UserProvider } from '../../src';

type FetchUserMock = {
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

export const withUser = (user?: UserProfile): React.ComponentType => {
  return (props: any): React.ReactElement => <UserProvider {...props} user={user} />;
};

export const fetchUserMock = (): Promise<FetchUserMock> => {
  return Promise.resolve({ json: (): Promise<UserProfile> => Promise.resolve(user) });
};

export const fetchUserFailureMock = (): Promise<FetchUserMock> => Promise.reject(new Error('Error'));
