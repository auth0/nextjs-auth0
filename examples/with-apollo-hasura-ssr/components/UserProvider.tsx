import { IClaims } from '@auth0/nextjs-auth0/dist/session/session'
import { createContext } from 'react'

export type UserContext = Readonly<{
  user: IClaims | null;
  loading: boolean;
}>

export const UserProvider = createContext<UserContext>({ user: null, loading: false })