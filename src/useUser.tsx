import { useContext, useEffect, useState } from 'react';
import fetchUserAtClient from './utils/fetchUserAtClient';
import { UserContext, UserProvider } from './utils/UserProvider';

/**
 * Ensures you get the user that is available, if there's a user available.
 */
export default function useUser(force = false, log = false): UserContext {
  const ctxUser = useContext(UserProvider);

  const [userState, setUserState] = useState({
    user: ctxUser.user,
    loading: ctxUser.user == null,
    hasFetched: ctxUser.user != null && !force
  });

  useEffect(() => {
    if (log) console.info('useUser effect called');

    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    async function fetcher() {
      const found = await fetchUserAtClient('/api/profile', force);
      if (log) console.info('useUser effect client-side fetch =>', found);

      setUserState({
        user: found,
        loading: false,
        hasFetched: true
      });
    }

    if (!userState.hasFetched) {
      fetcher();
    }
  }, [userState, setUserState, force, log]);

  if (log) console.info('useUser =>', userState);
  return userState;
}
