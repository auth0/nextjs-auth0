import { createContext } from 'react';
import { IClaims } from '../session/session';

export type UserContext = Readonly<{
  user: IClaims | null;
  loading: boolean;
}>;

export const UserProvider = createContext<UserContext>({ user: null, loading: false });
