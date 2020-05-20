import { useContext, useEffect, useState } from 'react'
import { UserContext, UserProvider } from '../components/UserProvider'
import fetchUserAtClient from './fetchUserAtClient'

/**
 * Ensures you get the user that is available, if there's a user available.
 */
export default function useUser(force = false, log = false): UserContext {
  const ctxUser = useContext(UserProvider)

  const [ userState, setUserState ] = useState({
    user: ctxUser.user,
    loading: ctxUser.user == null,
    hasFetched: ctxUser.user != null && !force
  })

  useEffect(() => {
    if (log) console.info('useUser effect called')

    async function fetcher() {
      const found = await fetchUserAtClient('/api/profile', force)
      if (log) console.info('useUser effect client-side fetch =>', found)

      setUserState({
        user: found,
        loading: false,
        hasFetched: true
      })
    }

    if (!userState.hasFetched) {
      fetcher()
    }
  }, [ userState, setUserState, force, log ])

  if (log) console.info('useUser =>', userState)
  return userState
}
