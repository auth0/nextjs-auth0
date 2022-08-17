import { withMiddlewareAuthRequired, getSession } from '@auth0/nextjs-auth0/middleware';
import { NextResponse } from 'next/server';

export default withMiddlewareAuthRequired(function middleware(req) {
  const session = getSession(req);
  console.log(req.url, session.user);
  return NextResponse.next();
});
