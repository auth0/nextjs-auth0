import { getSession, withApiAuthRequired } from '@auth0/nextjs-auth0/edge';
import { NextResponse } from 'next/server';

const GET = withApiAuthRequired(async () => {
  const session = await getSession();

  return NextResponse.json(session?.user);
});

export { GET };

export const runtime = 'edge';
