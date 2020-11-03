import React from 'react';
import { UserProfile, UserProvider } from '../../src';

type FetchMock = {
  ok: boolean;
  json: (() => Promise<UserProfile>) | undefined;
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

export const withUser = (user: UserProfile | null) => {
  return ({ children }: React.PropsWithChildren<void>): React.ReactElement => (
    <UserProvider user={user}>{children}</UserProvider>
  );
};

export const fetchUserMock = (): FetchMock => ({
  ok: true,
  json: (): Promise<UserProfile> => Promise.resolve(user)
});

export const fetchUserFailureMock = (): FetchMock => ({
  ok: false,
  json: undefined
});
