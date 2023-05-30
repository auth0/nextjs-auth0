import { handleAuth, handleProfile, Session } from '@auth0/nextjs-auth0';
import { NextRequest } from 'next/server';

export const GET = handleAuth({
  onError(req: Request, error: Error) {
    console.error(error);
  }
});
