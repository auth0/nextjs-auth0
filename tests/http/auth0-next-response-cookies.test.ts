import { cookies as nextCookies } from 'next/headers';
import { Auth0NextResponseCookies } from '../../src/http';
import { NextResponse } from 'next/server';

jest.mock('next/headers');

describe('auth0-next-response', () => {
  it('should set a cookie', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    jest.mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.setCookie('foo', 'bar');
    expect(res.cookies.get('foo')?.value).toEqual('bar');
  });

  it('should delete cookies', async () => {
    const cookies = new Auth0NextResponseCookies();
    const res = new NextResponse();
    jest.mocked(nextCookies).mockImplementation(() => res.cookies as any);
    cookies.clearCookie('foo');
    expect(res.headers.get('set-cookie')).toEqual('foo=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  });
});
