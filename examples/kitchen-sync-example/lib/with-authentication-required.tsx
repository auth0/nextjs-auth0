import { useRouter } from 'next/router';
import { ComponentType, FC, useEffect } from 'react';
import { useUser } from '@auth0/nextjs-auth0';

const defaultReturnTo = '';
const defaultOnRedirecting = () => <></>;

export default function withAuthenticationRequired<P extends object>(Component: ComponentType<P>, options: any = {}): FC<P> {
  return function withAuthenticationRequired(props: P): JSX.Element {
    const { user, loading } = useUser();
    const router = useRouter();
    const { returnTo = defaultReturnTo, onRedirecting = defaultOnRedirecting } = options;

    useEffect(() => {
      if (loading || !!user) {
        return;
      }

      
      router.push('/api/auth/login?returnTo=' + returnTo);
    }, [loading, !!user, returnTo]);

    return !!user ? <Component {...props} /> : onRedirecting();
  };
}
