import { handleAuth, handleProfile } from '@auth0/nextjs-auth0';

export const GET = handleAuth({
  profile: handleProfile({ refetch: true }),
  onError(req: Request, error: Error) {
    console.error(error);
  }
});
