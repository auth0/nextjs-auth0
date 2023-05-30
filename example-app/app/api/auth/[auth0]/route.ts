import { handleAuth, handleProfile, Session } from '@auth0/nextjs-auth0';
import { NextRequest } from 'next/server';

const afterRefetch = (req: NextRequest, session: Session) => {
  return { ...session, foo: 'bar' };
};

export const GET = handleAuth({
  profile: handleProfile({
    refetch: true,
    afterRefetch
  }),
  onError(req: Request, error: Error) {
    console.error(error);
  }
});
