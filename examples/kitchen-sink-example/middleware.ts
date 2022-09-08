import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/middleware';
import { NextResponse } from 'next/server';

export default withMiddlewareAuthRequired(function mw() {
  const res = NextResponse.next();
  res.cookies.set('mycookie', Math.floor(Math.random() * 100));
  return res;
});

export const config = {
  matcher: '/profile-ssr'
};
